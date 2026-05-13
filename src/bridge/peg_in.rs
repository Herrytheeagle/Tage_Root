// =============================================================================
// src/bridge/peg_in.rs — Bridge Peg-In (BTC → L2 Credit)
// =============================================================================
//
// The peg-in process moves BTC from the user's wallet into the bridge's
// custody so that the equivalent value can be represented as an L2 position.
//
// Path A (BIP-119 / OP_CTV active)
// ---------------------------------
//   1. The bridge generates a `CtvBridgeTemplate` for this deposit:
//      • `sequencer_update` template — lets the sequencer roll state forward.
//      • `user_exit` template        — lets the user reclaim BTC unilaterally
//                                      after `EXIT_TIMELOCK_BLOCKS`.
//   2. Both templates are compiled into Tapscript leaves and embedded in a
//      Taproot output (BIP-341) whose internal key is the NUMS point (so the
//      key path is provably unspendable).
//   3. The bridge returns the P2TR `script_pubkey` and the template metadata.
//   4. The user broadcasts a transaction paying to that `script_pubkey`.
//   5. After `CONFIRMATION_DEPTH` blocks, the bridge mints an equivalent L2
//      credit for the user.
//
// Path B (BitVM / no OP_CTV)
// --------------------------
//   See `bitvm_bridge.rs` — the peg-in address is instead a Taproot output
//   controlled by a pre-signed BitVM transaction tree.
//
// References
// ----------
// BIP-119 §"Applications": https://github.com/bitcoin/bips/blob/master/bip-0119.mediawiki
// BIP-341 §"Constructing and Spending": https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
// Research paper §5.2: "Proposed Architecture"

use crate::{
    covenant::{
        ctv::{build_tapscript_ctv_leaf, CtvBridgeTemplate, CtvTemplate},
        taproot::{TapLeaf, TapTree, TaprootBuilder, NUMS_KEY},
    },
    error::{BtcFiError, Result},
    execution::state::L2State,
    types::{Address, Amount, BlockHeight, DepositStatus, OutPoint, Script, TxOutput, U256},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Number of Bitcoin confirmations required before the bridge credits the L2.
///
/// 6 confirmations (≈ 60 minutes) is the traditional merchant standard for
/// large payments; bridges typically require more for high-value deposits.
pub const CONFIRMATION_DEPTH: u32 = 6;

/// The relative timelock (in blocks) before a user can exit unilaterally.
///
/// 144 blocks ≈ 24 hours.  This gives the sequencer time to process
/// the peg-out cooperatively before the user can force-exit.
///
/// In the CTV template, this is encoded as:
///   `nSequence = 0xFFFF_FFFF - EXIT_TIMELOCK_BLOCKS`  (BIP-68 relative timelock)
pub const EXIT_TIMELOCK_BLOCKS: u32 = 144;

/// Minimum deposit amount.  Below this, the bridge cannot profitably process
/// the transaction given on-chain fee requirements.
pub const MIN_DEPOSIT_SATS: u64 = 100_000; // 0.001 BTC

// ── Deposit record ────────────────────────────────────────────────────────────

/// A record of a confirmed or pending BTC deposit in the bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deposit {
    /// The on-chain UTXO that holds the locked BTC.
    pub outpoint: OutPoint,

    /// The amount locked (net of the on-chain fee from the user's peg-in tx).
    pub amount: Amount,

    /// The L2 address (public key or account identifier) to credit.
    pub l2_recipient: String,

    /// The CTV bridge templates for this deposit (Path A).
    ///
    /// `None` if this deposit was created with the BitVM path (Path B).
    pub ctv_template: Option<CtvBridgeTemplate>,

    /// The P2TR scriptPubKey the user paid to.
    pub peg_address_script: Script,

    /// Current lifecycle status.
    pub status: DepositStatus,

    /// Block height at which the deposit was first confirmed.
    pub confirmed_height: Option<BlockHeight>,
}

// ── PegInManager ──────────────────────────────────────────────────────────────

/// Manages the lifecycle of all bridge deposits.
///
/// In production this state would be persisted to a database and replicated
/// across bridge operators.  For this reference implementation it is an
/// in-memory `HashMap`.
#[derive(Debug, Default)]
pub struct PegInManager {
    /// Map of deposit UTXO outpoint → deposit record.
    deposits: HashMap<String, Deposit>,
}

impl PegInManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Generate a peg-in address (P2TR scriptPubKey) for a new deposit.
    ///
    /// # Arguments
    /// * `l2_recipient`     — The L2 account identifier to credit on confirmation.
    /// * `expected_amount`  — The amount the user intends to deposit.
    /// * `current_height`   — Current chain tip, used to set the exit timelock.
    ///
    /// # Returns
    /// A tuple of `(peg_script, bridge_template)`:
    /// * `peg_script`      — The P2TR scriptPubKey the user should pay to.
    /// * `bridge_template` — The CTV templates for sequencer update and exit.
    ///
    /// # Design
    ///
    /// The Taproot tree has exactly two leaves:
    ///
    /// ```text
    ///     Root
    ///    /    \
    ///  Leaf-A  Leaf-B
    ///  (sequencer CTV)  (user-exit CTV)
    /// ```
    ///
    /// Both leaves use `OP_CTV` (BIP-119).  The internal key is `NUMS_KEY`
    /// (BIP-341 §"Constructing"), making the key path unspendable.
    pub fn create_peg_address(
        &self,
        l2_recipient: &str,
        expected_amount: Amount,
        current_height: BlockHeight,
    ) -> Result<(Script, CtvBridgeTemplate)> {
        // Guard: reject dust deposits.
        if expected_amount < Amount::DUST_P2TR {
            return Err(BtcFiError::BelowDustThreshold {
                amount: expected_amount.sats(),
                threshold: Amount::DUST_P2TR.sats(),
            });
        }

        // Compute the exit block height (relative timelock from now).
        let exit_height = current_height.add_blocks(EXIT_TIMELOCK_BLOCKS);

        // Build the sequencer-update CTV template.
        // The sequencer can spend this output into a new state-commitment UTXO
        // that carries the same value (minus its operating fee).
        let sequencer_output_script = TaprootBuilder::new(NUMS_KEY)
            .build()
            .unwrap()
            .script_pubkey();
        let sequencer_tmpl = CtvTemplate {
            nversion: 2,
            nlocktime: 0,
            sequences: vec![0xffff_fffe], // no relative timelock on sequencer path
            outputs: vec![TxOutput {
                value: expected_amount
                    .checked_sub(Amount(1_000)) // subtract 1000 sat sequencer fee
                    .unwrap_or(expected_amount),
                script: sequencer_output_script,
            }],
            input_index: 0,
            label: Some(format!("sequencer-update:{l2_recipient}")),
        };

        // Build the user-exit CTV template.
        // After EXIT_TIMELOCK_BLOCKS the user can claim back their BTC without
        // the sequencer.  The nlocktime is set to the absolute exit height so
        // that the spending tx is only valid at or after that height.
        let user_script = TaprootBuilder::new(NUMS_KEY)
            .build()
            .unwrap()
            .script_pubkey();
        let user_exit_tmpl = CtvTemplate {
            nversion: 2,
            nlocktime: exit_height.0,
            // Relative timelock via nSequence encoding (BIP-68):
            //   0xFFFF_FFFE is the maximum non-final sequence with no relative lock.
            //   For a block-based lock: 0x0000_0000 | EXIT_TIMELOCK_BLOCKS
            sequences: vec![EXIT_TIMELOCK_BLOCKS],
            outputs: vec![TxOutput {
                value: expected_amount
                    .checked_sub(Amount(500)) // subtract 500 sat exit fee
                    .unwrap_or(expected_amount),
                script: user_script,
            }],
            input_index: 0,
            label: Some(format!("user-exit:{l2_recipient}")),
        };

        // Compile each template into a Tapscript CTV leaf script.
        let seq_hash = sequencer_tmpl.hash();
        let exit_hash = user_exit_tmpl.hash();

        let seq_leaf = TapLeaf::new(build_tapscript_ctv_leaf(&seq_hash));
        let exit_leaf = TapLeaf::new(build_tapscript_ctv_leaf(&exit_hash));

        // Build a two-leaf Taproot tree (BIP-341).
        let tree = TapTree::Branch(
            Box::new(TapTree::Leaf(seq_leaf)),
            Box::new(TapTree::Leaf(exit_leaf)),
        );

        // Finalise the Taproot output with the NUMS internal key.
        // The NUMS key ensures the key path is provably unspendable (BIP-341).
        let taproot_output = TaprootBuilder::new(NUMS_KEY).add_tree(tree).build()?;

        let peg_script = taproot_output.script_pubkey();

        let bridge_template = CtvBridgeTemplate {
            sequencer_update: sequencer_tmpl,
            user_exit: user_exit_tmpl,
            exit_after_height: exit_height,
        };

        Ok((peg_script, bridge_template))
    }

    /// Record a new deposit after the user's peg-in transaction has been
    /// broadcast (but not yet confirmed).
    pub fn register_deposit(
        &mut self,
        state: &mut L2State,
        outpoint: OutPoint,
        amount: Amount,
        l2_recipient: String,
        peg_script: Script,
        ctv_template: CtvBridgeTemplate,
    ) -> Result<()> {
        if amount.sats() < MIN_DEPOSIT_SATS {
            return Err(BtcFiError::BelowDustThreshold {
                amount: amount.sats(),
                threshold: MIN_DEPOSIT_SATS,
            });
        }

        let key = outpoint.to_string();
        let deposit = Deposit {
            outpoint,
            amount,
            l2_recipient,
            ctv_template: Some(ctv_template),
            peg_address_script: peg_script,
            status: DepositStatus::Pending,
            confirmed_height: None,
        };
        self.deposits.insert(key, deposit);

        // Persist this deposit amount into the shared global L2 state root.
        // This is a minimal wiring example showing that the bridge writes to
        // shared state instead of only keeping an isolated HashMap.
        let bridge_state_address = Address::zero();
        let deposit_total_slot = U256::from_u64(1);
        let previous_total = state.read_storage(&bridge_state_address, &deposit_total_slot);
        let new_total = U256::from_u64(previous_total.as_u64().saturating_add(amount.sats()));
        state.write_storage(&bridge_state_address, &deposit_total_slot, new_total);

        Ok(())
    }

    /// Mark a deposit as confirmed once it reaches `CONFIRMATION_DEPTH` blocks.
    ///
    /// Returns the L2 recipient and amount so the caller can issue the L2 credit.
    pub fn confirm_deposit(
        &mut self,
        outpoint: &OutPoint,
        confirm_height: BlockHeight,
    ) -> Result<(String, Amount)> {
        let key = outpoint.to_string();
        let deposit = self
            .deposits
            .get_mut(&key)
            .ok_or_else(|| BtcFiError::DepositNotFound { txid: key })?;

        deposit.status = DepositStatus::Confirmed;
        deposit.confirmed_height = Some(confirm_height);

        Ok((deposit.l2_recipient.clone(), deposit.amount))
    }

    /// Look up a deposit by outpoint.
    pub fn get_deposit(&self, outpoint: &OutPoint) -> Option<&Deposit> {
        self.deposits.get(&outpoint.to_string())
    }

    /// Total value of all confirmed deposits currently held by the bridge.
    pub fn total_locked_value(&self) -> Amount {
        self.deposits
            .values()
            .filter(|d| matches!(d.status, DepositStatus::Confirmed))
            .fold(Amount(0), |acc, d| acc.checked_add(d.amount).unwrap_or(acc))
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        execution::state::L2State,
        types::{Hash256, TxId},
    };

    fn test_outpoint() -> OutPoint {
        OutPoint {
            txid: TxId([1u8; 32]),
            vout: 0,
        }
    }

    #[test]
    fn creates_peg_address_successfully() {
        let mgr = PegInManager::new();
        let (script, tmpl) = mgr
            .create_peg_address("user123", Amount(1_000_000), BlockHeight(800_000))
            .unwrap();

        assert_eq!(script.len(), 34, "P2TR scriptPubKey must be 34 bytes");
        assert_eq!(script.as_bytes()[0], 0x51, "Must start with OP_1");
        // Exit timelock should be 144 blocks ahead.
        assert_eq!(tmpl.exit_after_height.0, 800_144);
    }

    #[test]
    fn rejects_dust_deposit() {
        let mgr = PegInManager::new();
        let result = mgr.create_peg_address("user", Amount(100), BlockHeight(0));
        assert!(matches!(result, Err(BtcFiError::BelowDustThreshold { .. })));
    }

    #[test]
    fn confirm_deposit_lifecycle() {
        let mut mgr = PegInManager::new();
        let mut state = L2State::new();
        let op = test_outpoint();

        let (script, tmpl) = mgr
            .create_peg_address("alice", Amount(500_000), BlockHeight(800_000))
            .unwrap();

        mgr.register_deposit(
            &mut state,
            op,
            Amount(500_000),
            String::from("alice"),
            script,
            tmpl,
        )
        .unwrap();

        let (recipient, amount) = mgr.confirm_deposit(&op, BlockHeight(800_006)).unwrap();

        assert_eq!(recipient, "alice");
        assert_eq!(amount.sats(), 500_000);
        assert_eq!(mgr.total_locked_value().sats(), 500_000);

        let bridge_state_address = Address::zero();
        let deposit_total_slot = U256::from_u64(1);
        assert_eq!(
            state
                .read_storage(&bridge_state_address, &deposit_total_slot)
                .as_u64(),
            500_000
        );
        assert_ne!(state.trie.state_root(), Hash256([0u8; 32]));
    }
}
