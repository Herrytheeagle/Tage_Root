// =============================================================================
// src/bridge/bitvm_bridge.rs — Path B: BitVM Optimistic Bridge
// =============================================================================
//
// When BIP-119 (OP_CTV) is not active on Bitcoin mainnet, the trust-minimised
// peg mechanism falls back to BitVM-style optimistic verification.
//
// How BitVM bridges work (simplified)
// ------------------------------------
// 1. Before the peg-in, the bridge operator and the user pre-sign a tree of
//    transactions encoding the exit logic.  Each leaf of this tree represents
//    a possible state of the bridge computation.
//
// 2. The user locks BTC in a Taproot UTXO (BIP-341) whose spending conditions
//    are defined by the pre-signed transaction tree.
//
// 3. The bridge operator publishes a claim about the bridge state.
//
// 4. If the claim is incorrect, any online challenger (verifier) can submit a
//    fraud proof.  The bisection protocol narrows the dispute to a single
//    computation step that can be verified on-chain with a Bitcoin script.
//
// 5. If no valid fraud proof is submitted within the CHALLENGE_WINDOW_BLOCKS,
//    the operator's claim is accepted as final.
//
// Trust tradeoffs vs. OP_CTV (Path A)
// -------------------------------------
// | Property              | Path A (CTV)   | Path B (BitVM)         |
// |-----------------------|----------------|------------------------|
// | On-chain enforcement  | Native script  | Optimistic (challenge) |
// | Operator honesty      | Not required   | Required OR challenged |
// | Liveness requirement  | None           | Challenger must be on  |
// | Tx overhead           | ~3 txs         | 3–7 txs (dispute path) |
// | BIP dependency        | BIP-119        | None (mainnet-ready)   |
//
// Reference: Linus, R. (2023). BitVM: Compute Anything on Bitcoin. bitvm.org.
// Reference: Linus et al. (2024). BitVM2: Bridging Bitcoin to Second Layers.
// Research paper §3.4: "BitVM and Optimistic Computation"
// Research paper §5.4: "Path B — BitVM Optimistic Verification"

use serde::{Deserialize, Serialize};
use crate::{
    error::{BtcFiError, Result},
    types::{Amount, BlockHeight, Hash256, OutPoint, Script, TxId},
    utils::hash::sha256d,
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Number of blocks the verifier has to submit a fraud proof after the operator
/// makes a claim.
///
/// This corresponds to the dispute window in optimistic rollup terminology.
/// 2016 blocks ≈ 2 weeks — chosen to give verifiers enough time to detect
/// and challenge fraudulent claims even under network congestion.
pub const CHALLENGE_WINDOW_BLOCKS: u32 = 2016;

/// Maximum number of bisection rounds in the fraud-proof protocol.
///
/// The BitVM bisection protocol halves the disputed computation range each
/// round.  For a computation with N steps:
///   rounds = ceil(log2(N))
///
/// For typical BTCFi bridge computations (≤ 2^32 steps):
///   max rounds = 32
pub const MAX_BISECTION_ROUNDS: u32 = 32;

// ── Operator claim ────────────────────────────────────────────────────────────

/// A claim made by the bridge operator about the state of a BitVM computation.
///
/// In the bridge context, this is a claim that a specific L2 state transition
/// is valid and that the associated peg-out should be honoured.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorClaim {
    /// The deposit UTXO this claim relates to.
    pub deposit_outpoint: OutPoint,

    /// The claimed output state hash (Merkle root of the claimed L2 state).
    pub claimed_state_root: Hash256,

    /// The block height at which this claim was published on-chain.
    pub published_at: BlockHeight,

    /// The block height after which this claim can no longer be challenged.
    pub challenge_deadline: BlockHeight,

    /// Whether this claim has been finalised (challenge window expired without
    /// a successful fraud proof).
    pub finalised: bool,
}

impl OperatorClaim {
    /// Construct a new operator claim.
    pub fn new(
        deposit_outpoint: OutPoint,
        claimed_state_root: Hash256,
        published_at: BlockHeight,
    ) -> Self {
        let deadline = published_at.add_blocks(CHALLENGE_WINDOW_BLOCKS);
        Self {
            deposit_outpoint,
            claimed_state_root,
            published_at,
            challenge_deadline: deadline,
            finalised: false,
        }
    }

    /// Returns `true` if the challenge window has expired and no fraud proof
    /// was submitted — the claim can now be treated as final.
    pub fn can_finalise(&self, current_height: BlockHeight) -> bool {
        !self.finalised && current_height.is_past(self.challenge_deadline)
    }
}

// ── Bisection state ───────────────────────────────────────────────────────────

/// Tracks the state of an ongoing bisection dispute between a challenger and
/// the operator.
///
/// BitVM §"Bisection Protocol":
///   The prover (operator) and verifier (challenger) engage in a binary search
///   over the computation trace until they agree on a single step where they
///   disagree.  That step is then verified directly on Bitcoin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BisectionState {
    /// The claim being disputed.
    pub claim: OperatorClaim,

    /// Current low bound of the disputed computation range.
    pub step_lo: u64,

    /// Current high bound of the disputed computation range.
    pub step_hi: u64,

    /// Number of bisection rounds completed so far.
    pub rounds_completed: u32,

    /// Hash of the operator's computation trace at the midpoint.
    /// Set by the operator during each bisection round.
    pub midpoint_hash: Option<Hash256>,
}

impl BisectionState {
    /// Initialise a new bisection over a computation range of `total_steps`.
    pub fn new(claim: OperatorClaim, total_steps: u64) -> Self {
        Self {
            claim,
            step_lo: 0,
            step_hi: total_steps,
            rounds_completed: 0,
            midpoint_hash: None,
        }
    }

    /// The midpoint step index for the current bisection round.
    pub fn midpoint(&self) -> u64 {
        (self.step_lo + self.step_hi) / 2
    }

    /// The challenger accepts the operator's midpoint trace hash as correct and
    /// narrows the dispute to the upper half.
    ///
    /// Called when the challenger agrees that `midpoint_hash` correctly
    /// represents the computation state at the midpoint.
    pub fn challenger_accepts_mid(&mut self) -> Result<()> {
        self.step_lo = self.midpoint();
        self.rounds_completed += 1;
        self.midpoint_hash = None;
        self.check_max_rounds()
    }

    /// The challenger rejects the operator's midpoint trace hash (believes it
    /// is wrong) and narrows the dispute to the lower half.
    pub fn challenger_rejects_mid(&mut self) -> Result<()> {
        self.step_hi = self.midpoint();
        self.rounds_completed += 1;
        self.midpoint_hash = None;
        self.check_max_rounds()
    }

    /// Returns `true` when the bisection has narrowed to a single step.
    pub fn is_resolved(&self) -> bool {
        self.step_hi - self.step_lo <= 1
    }

    fn check_max_rounds(&self) -> Result<()> {
        if self.rounds_completed > MAX_BISECTION_ROUNDS {
            return Err(BtcFiError::BitvmFraudProofInvalid {
                step: self.rounds_completed,
                reason: "Exceeded maximum bisection rounds".into(),
            });
        }
        Ok(())
    }
}

// ── Fraud proof ───────────────────────────────────────────────────────────────

/// A fraud proof submitted by a challenger to disprove an operator claim.
///
/// Once the bisection has identified a single disputed step, the challenger
/// provides the pre-state and the expected post-state.  A Bitcoin script
/// verifies that applying the operation to the pre-state does NOT produce
/// the operator's claimed post-state, proving fraud.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FraudProof {
    /// The disputed computation step index.
    pub step: u32,

    /// Hash of the computation state BEFORE the disputed step.
    pub pre_state_hash: Hash256,

    /// Hash of the computation state AFTER the disputed step, as computed by
    /// the CHALLENGER (the correct value).
    pub post_state_hash: Hash256,

    /// The operation executed at `step` (opcode + operands, serialised).
    pub operation: Vec<u8>,

    /// Merkle proof showing `pre_state_hash` is in the operator's trace.
    pub merkle_proof: Vec<Hash256>,
}

impl FraudProof {
    /// Verify this fraud proof against the operator's claimed post-state hash.
    ///
    /// Returns `Ok(())` if the proof is valid (i.e. the operator's claim is
    /// demonstrably wrong).
    ///
    /// # How verification works
    ///
    /// 1. Reconstruct the expected post-state by applying `operation` to
    ///    `pre_state_hash`.  (In production: full script evaluation.)
    /// 2. Assert that the reconstructed post-state ≠ the operator's claimed
    ///    post-state.  If equal, the fraud proof is invalid.
    /// 3. Verify the Merkle proof that `pre_state_hash` is in the operator's
    ///    published trace commitment.
    ///
    /// This verification would be executed on-chain by a Bitcoin script.
    /// Here we simulate it off-chain.
    pub fn verify(&self, operator_claimed_post_state: &Hash256) -> Result<()> {
        // Simulate applying the operation to the pre-state.
        // In production: full computation re-execution.
        let mut data = Vec::new();
        data.extend_from_slice(&self.pre_state_hash.0);
        data.extend_from_slice(&self.operation);
        let recomputed_post = sha256d(&data);

        // The fraud proof is valid if the operator's claim differs from what
        // honest re-execution produces.
        if &recomputed_post == operator_claimed_post_state {
            return Err(BtcFiError::BitvmFraudProofInvalid {
                step: self.step,
                reason: "Recomputed post-state matches operator claim — not fraud".into(),
            });
        }

        // Verify the Merkle inclusion proof (simplified).
        let mut current = self.pre_state_hash;
        for sibling in &self.merkle_proof {
            let mut data = Vec::with_capacity(64);
            if current.0 <= sibling.0 {
                data.extend_from_slice(&current.0);
                data.extend_from_slice(&sibling.0);
            } else {
                data.extend_from_slice(&sibling.0);
                data.extend_from_slice(&current.0);
            }
            current = sha256d(&data);
        }
        // `current` is now the computed Merkle root — in production, assert
        // this matches the on-chain commitment.

        Ok(())
    }
}

// ── BitvmBridgeManager ────────────────────────────────────────────────────────

/// Manages the lifecycle of BitVM bridge claims, disputes, and payouts.
///
/// In production, the claim and dispute state would be tracked on-chain
/// (encoded in transaction outputs) and monitored by independent watchers.
/// This implementation tracks state in memory for reference purposes.
#[derive(Debug, Default)]
pub struct BitvmBridgeManager {
    /// Pending or finalised operator claims.
    claims: Vec<OperatorClaim>,

    /// Active bisection disputes, indexed by the deposit outpoint string.
    disputes: std::collections::HashMap<String, BisectionState>,
}

impl BitvmBridgeManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Submit an operator claim for a deposit.
    pub fn submit_claim(
        &mut self,
        deposit_outpoint:  OutPoint,
        claimed_state_root: Hash256,
        current_height:    BlockHeight,
    ) {
        let claim = OperatorClaim::new(deposit_outpoint, claimed_state_root, current_height);
        self.claims.push(claim);
    }

    /// A challenger initiates a dispute against the most recent claim for a deposit.
    ///
    /// Returns the initial `BisectionState` for the challenger to drive.
    pub fn initiate_dispute(
        &mut self,
        deposit_outpoint: &OutPoint,
        total_steps:       u64,
        current_height:    BlockHeight,
    ) -> Result<()> {
        let key = deposit_outpoint.to_string();

        // Find the most recent unfinalised claim for this outpoint.
        let claim = self.claims
            .iter()
            .rev()
            .find(|c| c.deposit_outpoint == *deposit_outpoint && !c.finalised)
            .ok_or_else(|| BtcFiError::DepositNotFound { txid: key.clone() })?
            .clone();

        // Cannot dispute after the challenge window closes.
        if current_height.is_past(claim.challenge_deadline) {
            return Err(BtcFiError::BitvmChallengeWindowExpired {
                block: claim.challenge_deadline.0,
            });
        }

        let bisection = BisectionState::new(claim, total_steps);
        self.disputes.insert(key, bisection);
        Ok(())
    }

    /// Finalise all claims whose challenge window has expired without dispute.
    ///
    /// Returns the list of outpoints whose claims are now final.
    pub fn finalise_expired_claims(&mut self, current_height: BlockHeight) -> Vec<OutPoint> {
        let mut finalised = Vec::new();
        for claim in &mut self.claims {
            if claim.can_finalise(current_height) {
                claim.finalised = true;
                finalised.push(claim.deposit_outpoint);
            }
        }
        finalised
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TxId;

    fn op() -> OutPoint {
        OutPoint { txid: TxId([9u8; 32]), vout: 0 }
    }

    #[test]
    fn claim_finalises_after_window() {
        let mut mgr = BitvmBridgeManager::new();
        mgr.submit_claim(op(), Hash256([1u8; 32]), BlockHeight(0));

        let done = mgr.finalise_expired_claims(BlockHeight(CHALLENGE_WINDOW_BLOCKS));
        assert_eq!(done.len(), 1);
    }

    #[test]
    fn claim_does_not_finalise_during_window() {
        let mut mgr = BitvmBridgeManager::new();
        mgr.submit_claim(op(), Hash256([1u8; 32]), BlockHeight(0));

        let done = mgr.finalise_expired_claims(BlockHeight(CHALLENGE_WINDOW_BLOCKS - 1));
        assert!(done.is_empty());
    }

    #[test]
    fn bisection_narrows_range() {
        let claim = OperatorClaim::new(op(), Hash256([1u8; 32]), BlockHeight(0));
        let mut bis = BisectionState::new(claim, 1024);

        assert_eq!(bis.midpoint(), 512);
        bis.challenger_rejects_mid().unwrap();
        assert_eq!(bis.step_hi, 512);
        assert_eq!(bis.midpoint(), 256);
    }
}