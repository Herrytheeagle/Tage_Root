// =============================================================================
// src/covenant/taproot.rs — BIP-340/341/342 Taproot Helpers
// =============================================================================
//
// Taproot (activated on Bitcoin mainnet at block 709,632 — November 2021)
// introduces three tightly coupled BIPs:
//
//   BIP-340  Schnorr Signatures for secp256k1
//   BIP-341  Pay-to-Taproot (P2TR) output type and spending rules
//   BIP-342  Validation of Taproot scripts (Tapscript)
//
// Together, they enable:
//   • Key-path spending  — a single Schnorr signature from the aggregate key.
//   • Script-path spending — reveal one leaf from a Merkle tree of scripts.
//
// For the BTCFi bridge, Taproot is used to construct a peg output whose
// Tapscript tree encodes both the sequencer-update CTV leaf and the
// user-exit CTV leaf.  The key path is set to a Nothing-Up-My-Sleeve (NUMS)
// point to disable key-path spending, ensuring that only the pre-committed
// script paths are valid.
//
// References
// ----------
// BIP-340: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
// BIP-341: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
// BIP-342: https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki
// Research paper §4.1: "BIP-340, BIP-341, and BIP-342: Taproot"

use serde::{Deserialize, Serialize};
use crate::{
    error::{BtcFiError, Result},
    types::{Hash256, Script, XOnlyPubKey},
    utils::hash::{tapleaf_hash, tapbranch_hash, taptweak_hash},
};

// ── NUMS internal key ─────────────────────────────────────────────────────────

/// A Nothing-Up-My-Sleeve (NUMS) x-only public key used to disable key-path
/// spending in peg outputs.
///
/// BIP-341 §"Constructing and Spending Taproot Outputs":
///   "If the spending conditions do not include a key path, the internal key
///    should be set to a point with no known discrete logarithm."
///
/// This specific NUMS point is the SHA-256 of the uncompressed generator G
/// of secp256k1, which has no known discrete log.  It is the same NUMS point
/// used in the BIP-341 test vectors.
pub const NUMS_KEY: XOnlyPubKey = XOnlyPubKey([
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
    0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
    0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
]);

/// SegWit version 1 witness program version byte.
/// BIP-341: P2TR outputs use witness version 1 (`OP_1` = 0x51).
pub const WITNESS_VERSION_TAPROOT: u8 = 0x51;

// ── TapLeaf ───────────────────────────────────────────────────────────────────

/// A single leaf in a Tapscript tree.
///
/// Each leaf contains a version byte and a script.  BIP-342 defines leaf
/// version `0xc0` for the initial Tapscript set.  Future leaf versions may
/// enable different script validation rules without a hard fork.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TapLeaf {
    /// Leaf version byte.  Use `0xc0` for standard Tapscript (BIP-342).
    pub version: u8,
    /// The Tapscript to be executed when this leaf is revealed.
    pub script:  Script,
}

impl TapLeaf {
    /// Construct a standard BIP-342 Tapscript leaf.
    pub fn new(script: Script) -> Self {
        Self { version: 0xc0, script }
    }

    /// Compute the `TapLeaf` tagged hash for this leaf.
    ///
    /// BIP-341 §"Script Trees":
    ///   `tapleaf_hash = tagged_hash("TapLeaf", version || compact_size(script) || script)`
    pub fn hash(&self) -> Hash256 {
        tapleaf_hash(self.script.as_bytes())
    }
}

// ── TapTree ───────────────────────────────────────────────────────────────────

/// A binary Merkle tree of Tapscript leaves.
///
/// BIP-341 allows up to 128 levels deep.  For the BTCFi bridge peg output
/// we only ever need a two-leaf tree (sequencer-update || user-exit).
///
/// The Merkle root is computed bottom-up: leaf hashes are combined via the
/// `TapBranch` tagged hash, always sorting the pair lexicographically to
/// ensure a canonical representation.
///
/// BIP-341 §"Script Trees":
///   "The Merkle root of the tree is computed by recursively combining pairs
///    of nodes using the TapBranch hash, where leaf ordering is determined by
///    the canonical sort."
#[derive(Debug, Clone)]
pub enum TapTree {
    /// A single leaf — no branching needed.
    Leaf(TapLeaf),
    /// A branch combining two sub-trees.
    Branch(Box<TapTree>, Box<TapTree>),
}

impl TapTree {
    /// Compute the Merkle root hash of this tree.
    ///
    /// For a `Leaf`, this is the `TapLeaf` hash.
    /// For a `Branch`, this is the `TapBranch` hash of the two subtree roots.
    pub fn merkle_root(&self) -> Hash256 {
        match self {
            TapTree::Leaf(leaf) => leaf.hash(),
            TapTree::Branch(left, right) => {
                tapbranch_hash(&left.merkle_root(), &right.merkle_root())
            }
        }
    }

    /// Validate the tree depth does not exceed the BIP-341 limit of 128 levels.
    pub fn depth(&self) -> usize {
        match self {
            TapTree::Leaf(_) => 0,
            TapTree::Branch(l, r) => 1 + l.depth().max(r.depth()),
        }
    }
}

// ── TaprootOutput ─────────────────────────────────────────────────────────────

/// A fully constructed Taproot output ready to be included in a transaction.
///
/// Contains the tweaked output key (for the witness program) and enough
/// metadata to construct spending witnesses for any leaf.
#[derive(Debug, Clone)]
pub struct TaprootOutput {
    /// The tweaked output x-only public key (`Q = P + t·G`).
    ///
    /// BIP-341 §"Taproot Output Key Computation":
    ///   `Q = internal_key + tagged_hash("TapTweak", P || merkle_root) · G`
    pub output_key: XOnlyPubKey,

    /// The internal (un-tweaked) key.  Stored for witness construction.
    pub internal_key: XOnlyPubKey,

    /// The script tree, if any (None = key-path only).
    pub tree: Option<TapTree>,
}

impl TaprootOutput {
    /// Build a P2TR scriptPubKey from this output.
    ///
    /// Format: `OP_1 <32-byte-x-only-output-key>`
    /// In hex:  `51 20 <32 bytes>`
    ///
    /// BIP-141 §"Segregated Witness":
    ///   A witness version 1 program is a 32-byte push preceded by `OP_1`.
    pub fn script_pubkey(&self) -> Script {
        let mut s = Vec::with_capacity(34);
        s.push(WITNESS_VERSION_TAPROOT); // OP_1 = 0x51
        s.push(0x20);                   // Push 32 bytes
        s.extend_from_slice(&self.output_key.0);
        Script(s)
    }

    /// The Merkle root of the script tree, or all-zeros if key-path only.
    ///
    /// Used in the `TapTweak` hash computation and stored in the control block
    /// of script-path spending witnesses.
    pub fn merkle_root_bytes(&self) -> Vec<u8> {
        match &self.tree {
            None       => Vec::new(), // empty merkle root for key-path only
            Some(tree) => tree.merkle_root().0.to_vec(),
        }
    }
}

// ── TaprootBuilder ────────────────────────────────────────────────────────────

/// Constructs a `TaprootOutput` from an internal key and an optional script tree.
///
/// # Example — build the BTCFi bridge peg output
/// ```rust
/// // Two CTV leaf scripts built by `build_tapscript_ctv_leaf`
/// let sequencer_leaf = TapLeaf::new(sequencer_ctv_script);
/// let exit_leaf      = TapLeaf::new(exit_ctv_script);
///
/// let peg_output = TaprootBuilder::new(NUMS_KEY)
///     .add_tree(TapTree::Branch(
///         Box::new(TapTree::Leaf(sequencer_leaf)),
///         Box::new(TapTree::Leaf(exit_leaf)),
///     ))
///     .build()?;
/// ```
pub struct TaprootBuilder {
    internal_key: XOnlyPubKey,
    tree:         Option<TapTree>,
}

impl TaprootBuilder {
    /// Create a new builder with the given internal key.
    ///
    /// For peg outputs where key-path spending must be disabled, pass
    /// `NUMS_KEY` here.
    pub fn new(internal_key: XOnlyPubKey) -> Self {
        Self { internal_key, tree: None }
    }

    /// Attach a script tree to this output.
    pub fn add_tree(mut self, tree: TapTree) -> Self {
        self.tree = Some(tree);
        self
    }

    /// Finalise the output, computing the tweaked output key.
    ///
    /// # Errors
    /// Returns `InvalidTaprootKey` if the internal key bytes are invalid,
    /// or `TaprootTreeTooDeep` if the tree exceeds 128 levels.
    ///
    /// # Key computation (BIP-341)
    ///
    ///   1. Compute `merkle_root` from the script tree (or use empty bytes).
    ///   2. Compute `t = tagged_hash("TapTweak", internal_key || merkle_root)`.
    ///   3. Output key `Q = P + t·G`.
    ///
    /// Because we operate in a pure-Rust context without secp256k1 library
    /// bindings, we simulate the output key as the SHA-256 of the tweak applied
    /// to the internal key bytes.  Production code must use a proper secp256k1
    /// scalar multiplication.
    pub fn build(self) -> Result<TaprootOutput> {
        // Validate the internal key (32 non-zero bytes required).
        if self.internal_key.0 == [0u8; 32] {
            return Err(BtcFiError::InvalidTaprootKey {
                reason: "All-zero internal key is invalid".into(),
            });
        }

        // Validate tree depth.
        if let Some(ref tree) = self.tree {
            let d = tree.depth();
            if d > 128 {
                return Err(BtcFiError::TaprootTreeTooDeep { depth: d });
            }
        }

        // Compute the Merkle root bytes.
        let merkle_root_bytes: Vec<u8> = self
            .tree
            .as_ref()
            .map(|t| t.merkle_root().0.to_vec())
            .unwrap_or_default();

        // Compute TapTweak: t = tagged_hash("TapTweak", P || merkle_root)
        let tweak = taptweak_hash(&self.internal_key.0, &merkle_root_bytes);

        // Derive output key: Q = P + t·G
        let internal_pk = secp256k1::XOnlyPublicKey::from_slice(&self.internal_key.0)
            .map_err(|_| BtcFiError::InvalidTaprootKey {
                reason: "Invalid internal key".into(),
            })?;
        let tweak_scalar = secp256k1::Scalar::from_be_bytes(tweak.0)
            .map_err(|_| BtcFiError::InvalidTaprootKey {
                reason: "Invalid tweak scalar".into(),
            })?;
        let secp = secp256k1::Secp256k1::new();
        let (output_key, _parity) = internal_pk.add_tweak(&secp, &tweak_scalar)
            .map_err(|_| BtcFiError::InvalidTaprootKey {
                reason: "Tweak addition failed".into(),
            })?;
        let output_key = XOnlyPubKey(output_key.serialize());

        Ok(TaprootOutput {
            output_key,
            internal_key: self.internal_key,
            tree: self.tree,
        })
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_leaf(byte: u8) -> TapLeaf {
        TapLeaf::new(Script(vec![byte, 0x51]))
    }

    #[test]
    fn tapleaf_hash_is_deterministic() {
        let l = dummy_leaf(0xb3);
        assert_eq!(l.hash(), l.hash());
    }

    #[test]
    fn tapbranch_is_commutative_via_tree() {
        let tree_ab = TapTree::Branch(
            Box::new(TapTree::Leaf(dummy_leaf(0x01))),
            Box::new(TapTree::Leaf(dummy_leaf(0x02))),
        );
        let tree_ba = TapTree::Branch(
            Box::new(TapTree::Leaf(dummy_leaf(0x02))),
            Box::new(TapTree::Leaf(dummy_leaf(0x01))),
        );
        assert_eq!(
            tree_ab.merkle_root(),
            tree_ba.merkle_root(),
            "TapBranch must be order-independent"
        );
    }

    #[test]
    fn builder_produces_p2tr_script() {
        let output = TaprootBuilder::new(NUMS_KEY)
            .add_tree(TapTree::Leaf(dummy_leaf(0x51)))
            .build()
            .unwrap();

        let spk = output.script_pubkey();
        assert_eq!(spk.len(), 34);
        assert_eq!(spk.as_bytes()[0], 0x51, "First byte must be OP_1");
        assert_eq!(spk.as_bytes()[1], 0x20, "Second byte must be push-32");
    }

    #[test]
    fn all_zero_key_is_rejected() {
        let zero_key = XOnlyPubKey([0u8; 32]);
        let result = TaprootBuilder::new(zero_key).build();
        assert!(matches!(result, Err(BtcFiError::InvalidTaprootKey { .. })));
    }
}