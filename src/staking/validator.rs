// =============================================================================
// src/staking/validator.rs — Validator Bonding and Reward Accounting
// =============================================================================
//
// Bitcoin has no native Proof-of-Stake consensus.  The yield that validators
// earn in this L2 comes from two sources (research paper §5.3):
//
//   1. Security provisioning fees — external protocols pay to "rent" Bitcoin's
//      economic security by having validators attest to their state.
//      This is analogous to EigenLayer restaking on Ethereum.
//
//   2. L2 sequencing fees — validators earn a share of L2 transaction fees
//      for ordering and including transactions in L2 blocks.
//
// Importantly, there is NO protocol inflation.  Every reward is sourced from
// fee income, not from new BTC issuance.  This is a fundamental difference
// from Ethereum staking rewards.
//
// Slashing conditions are implemented in `slashing.rs`.
//
// References
// ----------
// Research paper §2.3: "The Absence of Proof-of-Stake Consensus"
// Research paper §5.3: "Re-staking and security provisioning"

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::{
    error::{BtcFiError, Result},
    types::{Amount, BlockHeight, XOnlyPubKey},
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Minimum bond required to register as a validator.
///
/// Set at 0.1 BTC (10,000,000 sats) — large enough to make Sybil attacks
/// expensive, small enough to allow meaningful participation.
pub const MIN_BOND_SATS: u64 = 10_000_000;

/// Maximum number of active validators in the committee.
///
/// Bounded to keep the attestation signature aggregation overhead manageable.
/// Larger sets improve decentralisation at the cost of consensus efficiency.
pub const MAX_VALIDATORS: usize = 100;

/// Unbonding delay in blocks before a validator can withdraw their bond.
///
/// 2016 blocks ≈ 2 weeks — aligns with the BitVM challenge window so that
/// a validator cannot bond, act maliciously, and exit before being slashed.
pub const UNBONDING_DELAY_BLOCKS: u32 = 2_016;

// ── Validator state ───────────────────────────────────────────────────────────

/// The lifecycle state of a validator's bond.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatorStatus {
    /// Actively participating in consensus and earning rewards.
    Active,
    /// Validator has initiated unbonding; awaiting `UNBONDING_DELAY_BLOCKS`.
    Unbonding { initiated_at: BlockHeight },
    /// Bond has been fully slashed due to proven misbehaviour.
    Slashed,
    /// Bond has been returned; validator has exited.
    Exited,
}

/// A registered validator in the L2 staking set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    /// The validator's x-only Schnorr public key (BIP-340).
    ///
    /// Used for signature verification in consensus and for slashing proofs.
    pub pubkey: XOnlyPubKey,

    /// Total BTC bonded (satoshis).  Subject to slashing.
    pub bond: Amount,

    /// Rewards accumulated but not yet withdrawn (satoshis).
    pub pending_rewards: Amount,

    /// Total rewards ever earned by this validator (for analytics).
    pub lifetime_rewards: Amount,

    /// Current validator status.
    pub status: ValidatorStatus,

    /// Block height at which this validator was registered.
    pub registered_at: BlockHeight,

    /// Human-readable name or identifier (optional; off-chain only).
    pub name: Option<String>,
}

impl Validator {
    /// Returns `true` if this validator is eligible to participate in the
    /// current consensus round (active and bond not slashed below minimum).
    pub fn is_eligible(&self) -> bool {
        self.status == ValidatorStatus::Active && self.bond.sats() >= MIN_BOND_SATS
    }

    /// Apply a slash to this validator's bond.
    ///
    /// `slash_amount` is deducted from the bond.  If the bond falls below the
    /// minimum, the validator is ejected (status → Slashed).
    pub fn apply_slash(&mut self, slash_amount: Amount) {
        let new_bond = self.bond.checked_sub(slash_amount).unwrap_or(Amount(0));
        self.bond = new_bond;
        if new_bond.sats() < MIN_BOND_SATS {
            self.status = ValidatorStatus::Slashed;
        }
    }
}

// ── ValidatorRegistry ─────────────────────────────────────────────────────────

/// Registry of all validators, active and historical.
#[derive(Debug, Default)]
pub struct ValidatorRegistry {
    /// Map from pubkey hex string → Validator.
    validators: HashMap<String, Validator>,
}

impl ValidatorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new validator by bonding BTC.
    ///
    /// # Errors
    /// * `BondTooSmall`    — bond is below `MIN_BOND_SATS`.
    /// * `BondTooSmall`    — validator set is full (`MAX_VALIDATORS`).
    ///
    /// Research paper §5.3:
    ///   "BTC deposited in the execution layer can be used to secure other
    ///    protocols that need economic security — analogous to EigenLayer's
    ///    restaking model."
    pub fn register(
        &mut self,
        pubkey:          XOnlyPubKey,
        bond:            Amount,
        current_height:  BlockHeight,
        name:            Option<String>,
    ) -> Result<()> {
        if bond.sats() < MIN_BOND_SATS {
            return Err(BtcFiError::BondTooSmall {
                minimum: MIN_BOND_SATS,
                got:     bond.sats(),
            });
        }

        let active_count = self.validators
            .values()
            .filter(|v| v.status == ValidatorStatus::Active)
            .count();
        if active_count >= MAX_VALIDATORS {
            return Err(BtcFiError::BondTooSmall {
                minimum: MIN_BOND_SATS,
                got:     0, // reuse error; production would have a dedicated variant
            });
        }

        let key = pubkey.to_string();
        self.validators.insert(key, Validator {
            pubkey,
            bond,
            pending_rewards:  Amount(0),
            lifetime_rewards: Amount(0),
            status:           ValidatorStatus::Active,
            registered_at:    current_height,
            name,
        });

        log::info!("Validator {} registered with {} bond", pubkey, bond);
        Ok(())
    }

    /// Distribute a reward pool to all active validators, weighted by bond size.
    ///
    /// This simulates the distribution of sequencing fees or restaking revenues
    /// collected in a given epoch.
    ///
    /// # Design note
    /// Bond-weighted distribution incentivises validators to bond more BTC,
    /// increasing the economic security of the network.  The relationship is:
    ///
    ///   validator_reward = epoch_reward × (validator_bond / total_active_bond)
    pub fn distribute_rewards(&mut self, epoch_reward: Amount) -> Result<()> {
        // Compute total active bond for weighting.
        let total_bond: u64 = self.validators
            .values()
            .filter(|v| v.is_eligible())
            .map(|v| v.bond.sats())
            .sum();

        if total_bond == 0 {
            log::warn!("distribute_rewards: no active validators");
            return Ok(());
        }

        // Distribute proportionally.
        let total_reward = epoch_reward.sats();
        let mut distributed: u64 = 0;

        let pubkeys: Vec<String> = self.validators
            .values()
            .filter(|v| v.is_eligible())
            .map(|v| v.pubkey.to_string())
            .collect();

        for key in &pubkeys {
            if let Some(v) = self.validators.get_mut(key) {
                let share = total_reward * v.bond.sats() / total_bond;
                v.pending_rewards = v.pending_rewards
                    .checked_add(Amount(share))
                    .unwrap_or(v.pending_rewards);
                v.lifetime_rewards = v.lifetime_rewards
                    .checked_add(Amount(share))
                    .unwrap_or(v.lifetime_rewards);
                distributed += share;
            }
        }

        log::info!(
            "Distributed {} sats rewards across {} validators ({} undistributed due to rounding)",
            distributed,
            pubkeys.len(),
            total_reward.saturating_sub(distributed)
        );
        Ok(())
    }

    /// Claim pending rewards for a validator.
    pub fn claim_rewards(&mut self, pubkey: &XOnlyPubKey) -> Result<Amount> {
        let key = pubkey.to_string();
        let v = self.validators.get_mut(&key)
            .ok_or_else(|| BtcFiError::UnknownValidator { pubkey: key })?;

        let claimed = v.pending_rewards;
        v.pending_rewards = Amount(0);
        Ok(claimed)
    }

    /// Initiate unbonding for a validator.
    ///
    /// The validator stops earning rewards immediately.  After
    /// `UNBONDING_DELAY_BLOCKS` the bond can be withdrawn.
    pub fn initiate_unbonding(
        &mut self,
        pubkey:          &XOnlyPubKey,
        current_height:  BlockHeight,
    ) -> Result<BlockHeight> {
        let key = pubkey.to_string();
        let v = self.validators.get_mut(&key)
            .ok_or_else(|| BtcFiError::UnknownValidator { pubkey: key })?;

        v.status = ValidatorStatus::Unbonding {
            initiated_at: current_height,
        };
        let unlock_height = current_height.add_blocks(UNBONDING_DELAY_BLOCKS);
        log::info!("Validator {} unbonding; can exit at {}", pubkey, unlock_height);
        Ok(unlock_height)
    }

    /// Complete unbonding and return the bond amount.
    ///
    /// Only succeeds after `UNBONDING_DELAY_BLOCKS` have elapsed.
    pub fn complete_exit(
        &mut self,
        pubkey:          &XOnlyPubKey,
        current_height:  BlockHeight,
    ) -> Result<Amount> {
        let key = pubkey.to_string();
        let v = self.validators.get_mut(&key)
            .ok_or_else(|| BtcFiError::UnknownValidator { pubkey: key.clone() })?;

        let unlock_height = match v.status {
            ValidatorStatus::Unbonding { initiated_at } => {
                initiated_at.add_blocks(UNBONDING_DELAY_BLOCKS)
            }
            _ => return Err(BtcFiError::TimelockNotExpired {
                current: current_height.0,
                unlock:  0,
            }),
        };

        if !current_height.is_past(unlock_height) {
            return Err(BtcFiError::TimelockNotExpired {
                current: current_height.0,
                unlock:  unlock_height.0,
            });
        }

        let bond = v.bond;
        v.status = ValidatorStatus::Exited;
        v.bond   = Amount(0);
        Ok(bond)
    }

    /// Look up a validator by public key.
    pub fn get(&self, pubkey: &XOnlyPubKey) -> Option<&Validator> {
        self.validators.get(&pubkey.to_string())
    }

    /// Get a mutable reference to a validator.
    pub fn get_mut(&mut self, pubkey: &XOnlyPubKey) -> Option<&mut Validator> {
        self.validators.get_mut(&pubkey.to_string())
    }

    /// Look up a validator by public key.
    pub fn get_validator(&self, pubkey: &XOnlyPubKey) -> Option<&Validator> {
        self.get(pubkey)
    }

    /// Remove a validator from the registry.
    pub fn remove_validator(&mut self, pubkey: &XOnlyPubKey) -> Result<Validator> {
        let key = pubkey.to_string();
        self.validators.remove(&key)
            .ok_or_else(|| BtcFiError::UnknownValidator { pubkey: key })
    }

    /// Count of currently active validators.
    pub fn active_count(&self) -> usize {
        self.validators.values().filter(|v| v.is_eligible()).count()
    }

    /// Total BTC bonded by all active validators.
    pub fn total_active_bond(&self) -> Amount {
        self.validators
            .values()
            .filter(|v| v.is_eligible())
            .fold(Amount(0), |acc, v| acc.checked_add(v.bond).unwrap_or(acc))
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> XOnlyPubKey {
        XOnlyPubKey([n; 32])
    }

    #[test]
    fn register_and_count() {
        let mut reg = ValidatorRegistry::new();
        reg.register(key(1), Amount(MIN_BOND_SATS), BlockHeight(0), None).unwrap();
        reg.register(key(2), Amount(MIN_BOND_SATS * 2), BlockHeight(0), None).unwrap();
        assert_eq!(reg.active_count(), 2);
    }

    #[test]
    fn bond_too_small_rejected() {
        let mut reg = ValidatorRegistry::new();
        let result = reg.register(key(1), Amount(1_000), BlockHeight(0), None);
        assert!(matches!(result, Err(BtcFiError::BondTooSmall { .. })));
    }

    #[test]
    fn rewards_distributed_proportionally() {
        let mut reg = ValidatorRegistry::new();
        reg.register(key(1), Amount(MIN_BOND_SATS),     BlockHeight(0), None).unwrap();
        reg.register(key(2), Amount(MIN_BOND_SATS * 3), BlockHeight(0), None).unwrap();

        reg.distribute_rewards(Amount(100_000)).unwrap();

        let r1 = reg.get(&key(1)).unwrap().pending_rewards.sats();
        let r2 = reg.get(&key(2)).unwrap().pending_rewards.sats();
        // key(2) bonded 3× more, should get ~3× the reward.
        assert!(r2 > r1 * 2, "r2={} should be ~3x r1={}", r2, r1);
    }

    #[test]
    fn unbonding_timelock_enforced() {
        let mut reg = ValidatorRegistry::new();
        reg.register(key(1), Amount(MIN_BOND_SATS), BlockHeight(0), None).unwrap();
        reg.initiate_unbonding(&key(1), BlockHeight(0)).unwrap();

        // Cannot exit before the delay.
        let result = reg.complete_exit(&key(1), BlockHeight(UNBONDING_DELAY_BLOCKS - 1));
        assert!(matches!(result, Err(BtcFiError::TimelockNotExpired { .. })));

        // Can exit exactly at the delay.
        let bond = reg.complete_exit(&key(1), BlockHeight(UNBONDING_DELAY_BLOCKS)).unwrap();
        assert_eq!(bond.sats(), MIN_BOND_SATS);
    }
}