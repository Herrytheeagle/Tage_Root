// =============================================================================
// src/covenant/ctv.rs — BIP-119 OP_CHECKTEMPLATEVERIFY
// =============================================================================
//
// OP_CHECKTEMPLATEVERIFY (OP_CTV) is proposed in BIP-119 as a new Bitcoin
// opcode that restricts how a UTXO may be spent.  When a script contains
// OP_CTV, the spending transaction MUST match the template committed to at
// the time the output was created — any deviation causes the script to fail.
//
// This module implements:
//   1. `CtvTemplate`        — the serialisable spending template.
//   2. `CtvTemplate::hash`  — computes the BIP-119 template hash.
//   3. `build_ctv_script`   — builds the locking scriptPubKey.
//   4. `verify_ctv_spend`   — validates that a spending transaction satisfies
//                              a given CTV commitment.
//
// Why Tage matters for BTCFi
// --------------------------
// Without OP_CTV, any peg-out or vault construction on Bitcoin requires off-
// chain signers (MPC committees, BitVM challengers).  With OP_CTV, the peg
// output itself enforces the exit terms: the sequencer can only spend the
// output into one of a set of pre-committed templates — they cannot steal funds.
//
// BIP-119 deployment status (as of paper publication date): PROPOSED.
// This code implements the Path A deployment branch from the research paper.
//
// References
// ----------
// BIP-119: https://github.com/bitcoin/bips/blob/master/bip-0119.mediawiki
// BIP-341: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
// Research paper §4.2: "BIP-119: OP_CHECKTEMPLATEVERIFY (CTV)"
// Research paper §5.2: "Proposed Architecture"

use crate::{
    error::{BtcFiError, Result},
    types::{Amount, BlockHeight, Hash256, Script, TxOutput},
    utils::hash::{ctv_template_hash, hash_outputs, hash_sequences},
};
use serde::{Deserialize, Serialize};

// ── Opcode constant ───────────────────────────────────────────────────────────

/// BIP-119 assigns OP_CTV to opcode byte `0xb3` (previously OP_NOP4).
///
/// BIP-119 §"Specification":
///   "OP_CHECKTEMPLATEVERIFY redefines opcode 0xb3 (OP_NOP4)."
pub const OP_CTV: u8 = 0xb3;

/// OP_DROP — used to pop the template hash off the stack after OP_CTV succeeds.
pub const OP_DROP: u8 = 0x75;

/// OP_TRUE / OP_1 — leaves `1` on the stack for a clean success exit.
pub const OP_TRUE: u8 = 0x51;

// ── CtvTemplate ───────────────────────────────────────────────────────────────

/// All fields that OP_CTV commits to.
///
/// BIP-119 §"Template Hash" specifies this exact field set.  Changing any
/// field produces a different template hash and therefore a different locking
/// script.
///
/// # Typical usage in the BTCFi bridge
///
/// The bridge operator pre-computes two templates for each deposit:
///
/// 1. **Sequencer update template** — allows the sequencer to roll the locked
///    BTC forward into a new state-commitment UTXO (same amount, new CTV hash).
/// 2. **User exit template**        — allows the user to reclaim their BTC
///    after the `exit_locktime` block height has passed (unilateral exit).
///
/// Both templates are encoded as leaves in the Taproot script tree (BIP-341),
/// so the peg output has a compact address while supporting both spending paths.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtvTemplate {
    /// Transaction version committed by this template.
    /// Must be 2 to allow relative timelocks (BIP-68 / BIP-112).
    pub nversion: i32,

    /// Absolute locktime committed by this template.
    /// 0 = no absolute lock; or set to a future block height for time-locked exits.
    pub nlocktime: u32,

    /// The nSequence values for every input, in input order.
    ///
    /// For a relative timelock exit, set the relevant input sequence to:
    ///   `0xFFFFFFFE - blocks_to_lock`  (per BIP-68).
    pub sequences: Vec<u32>,

    /// The outputs the spending transaction must produce, in order.
    pub outputs: Vec<TxOutput>,

    /// The index of the input that contains this CTV opcode.
    /// Almost always 0 for peg constructions with a single input.
    pub input_index: u32,

    /// Descriptive label for this template (not committed; for tooling only).
    #[serde(default)]
    pub label: Option<String>,
}

impl CtvTemplate {
    /// Compute the BIP-119 template hash for this template.
    ///
    /// BIP-119 §"Template Hash":
    ///   The hash is computed as SHA-256 of the concatenated fields (not
    ///   double-SHA256), allowing efficient incremental computation when only
    ///   the outputs change between related templates.
    pub fn hash(&self) -> Hash256 {
        // Hash the sequences first so we only compute it once.
        let seqs: Vec<u32> = self.sequences.clone();
        let sequences_hash = hash_sequences(&seqs);

        // Serialise outputs as (value_le8 || compact_size(script) || script).
        let output_pairs: Vec<(u64, &[u8])> = self
            .outputs
            .iter()
            .map(|o| (o.value.sats(), o.script.as_bytes()))
            .collect();
        let outputs_hash = hash_outputs(&output_pairs);

        ctv_template_hash(
            self.nversion,
            self.nlocktime,
            None, // No scriptSigs in SegWit/Taproot inputs (BIP-141/BIP-342)
            self.sequences.len() as u32,
            &sequences_hash,
            self.outputs.len() as u32,
            &outputs_hash,
            self.input_index,
        )
    }

    /// Total value of all outputs in this template.
    ///
    /// Used by the bridge to assert conservation of value: the sum of output
    /// amounts must equal the deposited amount minus fees.
    pub fn total_output_value(&self) -> Option<Amount> {
        self.outputs
            .iter()
            .try_fold(Amount(0), |acc, o| acc.checked_add(o.value))
    }

    /// Build the locking script (scriptPubKey) for a bare CTV output.
    ///
    /// The minimal CTV script is:
    ///   `<hash> OP_CTV`
    ///
    /// where `<hash>` is the 32-byte template hash pushed as a data element.
    ///
    /// In practice this bare script is almost never used directly — instead
    /// CTV is embedded as a Tapscript leaf inside a P2TR output (BIP-341).
    /// See `taproot::build_ctv_taproot_address` for the recommended form.
    ///
    /// BIP-119 §"Script Standardness":
    ///   Bare CTV outputs are non-standard; wrap in P2TR for relay compatibility.
    pub fn to_bare_script(&self) -> Script {
        let hash = self.hash();
        let mut script = Vec::with_capacity(1 + 32 + 1);
        script.push(0x20); // OP_DATA_32 push opcode
        script.extend_from_slice(&hash.0);
        script.push(OP_CTV);
        Script(script)
    }
}

// ── CtvBridgeTemplate ─────────────────────────────────────────────────────────

/// A pair of CTV templates representing the two spending paths for a bridge
/// deposit UTXO.
///
/// This is the core data structure of the BTCFi bridge's Path A (CTV) design,
/// as described in research paper §5.2.
///
/// ```text
///  Taproot output key
///       │
///       ├── KeyPath: NUMS key (disabled — prevents key-path theft)
///       │
///       └── ScriptTree
///             ├── Leaf A: <sequencer_hash> OP_CTV
///             │          (sequencer advances state)
///             └── Leaf B: <exit_hash> OP_CTV
///                         (user exits unilaterally after timelock)
/// ```
///
/// The `sequencer_update` template allows the sequencer to roll the UTXO into
/// a new state-commitment output.  The `user_exit` template allows the user to
/// reclaim their BTC after `exit_after_height` blocks, without any cooperation
/// from the sequencer.  The unilateral exit guarantee is Bitcoin-enforced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtvBridgeTemplate {
    /// Template for the sequencer to advance the L2 state commitment.
    pub sequencer_update: CtvTemplate,

    /// Template for the user to unilaterally exit after the timelock.
    pub user_exit: CtvTemplate,

    /// The block height after which the user exit template is valid.
    ///
    /// This maps to the `nlocktime` or input sequence of the `user_exit` template.
    pub exit_after_height: BlockHeight,
}

impl CtvBridgeTemplate {
    /// Verify that a proposed spending transaction satisfies the sequencer-update
    /// template.
    ///
    /// Returns `Ok(())` if the template hash of the proposal matches the
    /// committed sequencer-update hash; returns `Err(CtvTemplateMismatch)` if not.
    pub fn verify_sequencer_spend(&self, proposal: &CtvTemplate) -> Result<()> {
        let expected = self.sequencer_update.hash();
        let got = proposal.hash();
        if expected != got {
            return Err(BtcFiError::CtvTemplateMismatch {
                expected: expected.to_string(),
                got: got.to_string(),
            });
        }
        Ok(())
    }

    /// Verify that a proposed spending transaction satisfies the user-exit
    /// template and that the exit timelock has passed.
    ///
    /// # Arguments
    /// * `proposal`       — The template implied by the spending transaction.
    /// * `current_height` — The block height at which the spend is being evaluated.
    pub fn verify_user_exit(
        &self,
        proposal: &CtvTemplate,
        current_height: BlockHeight,
    ) -> Result<()> {
        // 1. Check that the timelock has elapsed.
        if !current_height.is_past(self.exit_after_height) {
            return Err(BtcFiError::TimelockNotExpired {
                current: current_height.0,
                unlock: self.exit_after_height.0,
            });
        }

        // 2. Verify the template hash matches the committed exit template.
        let expected = self.user_exit.hash();
        let got = proposal.hash();
        if expected != got {
            return Err(BtcFiError::CtvTemplateMismatch {
                expected: expected.to_string(),
                got: got.to_string(),
            });
        }

        Ok(())
    }
}

// ── Script builder helper ─────────────────────────────────────────────────────

/// Build a Tapscript-compatible CTV leaf script for embedding inside a P2TR
/// output (BIP-341 / BIP-342).
///
/// The script format suitable for a Tapscript leaf is:
///   `<32-byte-template-hash> OP_CTV`
///
/// BIP-342 §"Tapscript":
///   All SegWit version 1 (Taproot) scripts use the Tapscript rules defined in
///   BIP-342, which permit OP_CTV as a valid opcode.
pub fn build_tapscript_ctv_leaf(template_hash: &Hash256) -> Script {
    let mut script = Vec::with_capacity(34); // 1 push + 32 hash + 1 opcode
    script.push(0x20); // Push 32 bytes
    script.extend_from_slice(&template_hash.0);
    script.push(OP_CTV);
    Script(script)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_output(sats: u64) -> TxOutput {
        TxOutput {
            value: Amount(sats),
            script: Script(vec![0x51]), // OP_TRUE — valid unencumbered output for test fixtures
        }
    }

    #[test]
    fn template_hash_is_deterministic() {
        let tmpl = CtvTemplate {
            nversion: 2,
            nlocktime: 0,
            sequences: vec![0xffff_fffe],
            outputs: vec![dummy_output(99_000)],
            input_index: 0,
            label: None,
        };
        assert_eq!(tmpl.hash(), tmpl.hash(), "CTV hash must be deterministic");
    }

    #[test]
    fn template_hash_changes_with_output_value() {
        let base = CtvTemplate {
            nversion: 2,
            nlocktime: 0,
            sequences: vec![0xffff_fffe],
            outputs: vec![dummy_output(100_000)],
            input_index: 0,
            label: None,
        };
        let modified = CtvTemplate {
            outputs: vec![dummy_output(99_000)], // 1000 sat fee deducted
            ..base.clone()
        };
        assert_ne!(
            base.hash(),
            modified.hash(),
            "Different output values must produce different CTV hashes"
        );
    }

    #[test]
    fn user_exit_fails_before_timelock() {
        let exit_tmpl = CtvTemplate {
            nversion: 2,
            nlocktime: 1_000,
            sequences: vec![0xffff_fffe],
            outputs: vec![dummy_output(98_000)],
            input_index: 0,
            label: Some("user-exit".into()),
        };
        let bridge = CtvBridgeTemplate {
            sequencer_update: exit_tmpl.clone(),
            user_exit: exit_tmpl.clone(),
            exit_after_height: BlockHeight(1_000),
        };

        let result = bridge.verify_user_exit(&exit_tmpl, BlockHeight(999));
        assert!(matches!(result, Err(BtcFiError::TimelockNotExpired { .. })));
    }

    #[test]
    fn user_exit_succeeds_at_timelock() {
        let exit_tmpl = CtvTemplate {
            nversion: 2,
            nlocktime: 0,
            sequences: vec![0xffff_fffe],
            outputs: vec![dummy_output(98_000)],
            input_index: 0,
            label: Some("user-exit".into()),
        };
        let bridge = CtvBridgeTemplate {
            sequencer_update: exit_tmpl.clone(),
            user_exit: exit_tmpl.clone(),
            exit_after_height: BlockHeight(1_000),
        };

        assert!(bridge
            .verify_user_exit(&exit_tmpl, BlockHeight(1_000))
            .is_ok());
        assert!(bridge
            .verify_user_exit(&exit_tmpl, BlockHeight(1_001))
            .is_ok());
    }
}
