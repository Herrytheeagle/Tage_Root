// =============================================================================
// src/utils/hash.rs — Hash Primitives
// =============================================================================
//
// Provides the hashing operations used throughout Bitcoin's scripting and
// signature verification system:
//
//   • SHA-256d (double SHA-256)  — used for TxId and block hash computation.
//   • Hash160 (SHA-256 + RIPEMD-160) — used for P2PKH / P2SH addresses.
//   • Tagged hash (BIP-340)      — domain-separated hashes used in Taproot
//                                   and Schnorr signature scheme.
//   • CTV template hash (BIP-119) — the commitment hash checked by OP_CTV.
//
// References
// ----------
// BIP-340 §"Tagged Hashes":
//   https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
// BIP-119 §"Template Hash":
//   https://github.com/bitcoin/bips/blob/master/bip-0119.mediawiki
// BIP-341 §"Taproot Output Key Computation":
//   https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki

use sha2::{Digest, Sha256};
use ripemd::Ripemd160;
use crate::types::Hash256;

// ── SHA-256d ──────────────────────────────────────────────────────────────────

/// Compute SHA-256(SHA-256(data)) — the "double-SHA256" used for Bitcoin
/// transaction IDs and block header hashes.
///
/// # Example
/// ```
/// let txid_bytes = sha256d(serialised_transaction);
/// ```
pub fn sha256d(data: &[u8]) -> Hash256 {
    let first  = Sha256::digest(data);
    let second = Sha256::digest(&first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    Hash256(out)
}

// ── Hash160 ───────────────────────────────────────────────────────────────────

/// Compute RIPEMD-160(SHA-256(data)) — used in P2PKH and P2SH output scripts.
///
/// Bitcoin uses the 20-byte Hash160 to shorten public keys and script hashes
/// in legacy address formats.
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let sha = Sha256::digest(data);
    let rmd = Ripemd160::digest(&sha);
    let mut out = [0u8; 20];
    out.copy_from_slice(&rmd);
    out
}

// ── BIP-340 Tagged Hash ───────────────────────────────────────────────────────

/// Compute a tagged hash as specified in BIP-340:
///
///   `tagged_hash(tag, msg) = SHA-256(SHA-256(tag) || SHA-256(tag) || msg)`
///
/// The double-prefix of `SHA-256(tag)` domain-separates different hash uses so
/// that collisions between, e.g., a TapLeaf hash and a TapBranch hash are
/// computationally infeasible even if the underlying data is identical.
///
/// BIP-340 §"Tagged Hashes":
///   "We use tagged hashes (as described in BIP-340) to domain-separate the
///    different types of hashes computed during Taproot output key computation."
///
/// Well-known tags used in this codebase:
/// | Tag string         | Used for                                |
/// |--------------------|-----------------------------------------|
/// | "TapLeaf"          | Hashing a Tapscript leaf (BIP-341)      |
/// | "TapBranch"        | Hashing two child nodes (BIP-341)       |
/// | "TapTweak"         | Tweaking the internal key (BIP-341)     |
/// | "BIP0340/nonce"    | Schnorr nonce generation (BIP-340)      |
/// | "BIP0340/aux"      | Auxiliary randomness masking (BIP-340)  |
/// | "BIP0340/challenge"| Schnorr challenge hash (BIP-340)        |
pub fn tagged_hash(tag: &str, msg: &[u8]) -> Hash256 {
    let tag_hash = Sha256::digest(tag.as_bytes());

    let mut hasher = Sha256::new();
    hasher.update(&tag_hash); // SHA-256(tag)
    hasher.update(&tag_hash); // SHA-256(tag)  (doubled as per BIP-340)
    hasher.update(msg);
    let result = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    Hash256(out)
}

// ── Taproot-specific tagged hashes (BIP-341) ──────────────────────────────────

/// Compute `TapLeaf` tagged hash for a Tapscript leaf.
///
/// BIP-341 §"Script Trees":
///   `tapleaf_hash = tagged_hash("TapLeaf", version || compact_size(script) || script)`
///
/// `version` is `0xc0` for the initial Tapscript leaf version (BIP-342).
pub fn tapleaf_hash(script_bytes: &[u8]) -> Hash256 {
    let mut data = Vec::with_capacity(1 + 9 + script_bytes.len());
    data.push(0xc0); // Tapscript leaf version (BIP-342)
    push_compact_size(&mut data, script_bytes.len() as u64);
    data.extend_from_slice(script_bytes);
    tagged_hash("TapLeaf", &data)
}

/// Compute `TapBranch` tagged hash for two child nodes in the Tapscript tree.
///
/// BIP-341 §"Script Trees":
///   `tapbranch_hash = tagged_hash("TapBranch", sort(left, right))`
///
/// The two children are sorted lexicographically before hashing to ensure the
/// tree representation is canonical regardless of construction order.
pub fn tapbranch_hash(left: &Hash256, right: &Hash256) -> Hash256 {
    let (a, b) = if left.0 <= right.0 {
        (left.as_bytes(), right.as_bytes())
    } else {
        (right.as_bytes(), left.as_bytes())
    };

    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(a);
    data.extend_from_slice(b);
    tagged_hash("TapBranch", &data)
}

/// Compute `TapTweak` tagged hash used to derive the Taproot output key.
///
/// BIP-341 §"Taproot Output Key Computation":
///   `taptweak = tagged_hash("TapTweak", internal_key || merkle_root)`
///
/// If the tree is empty (key-path only spend), `merkle_root` is the empty
/// byte slice.
pub fn taptweak_hash(internal_key: &[u8; 32], merkle_root: &[u8]) -> Hash256 {
    let mut data = Vec::with_capacity(32 + merkle_root.len());
    data.extend_from_slice(internal_key);
    data.extend_from_slice(merkle_root);
    tagged_hash("TapTweak", &data)
}

// ── BIP-119 CTV Template Hash ─────────────────────────────────────────────────

/// Serialise and hash the fields committed to by OP_CHECKTEMPLATEVERIFY.
///
/// BIP-119 §"Template Hash" specifies the following commitment:
///
///   `ctv_hash = SHA-256(`
///     `  nVersion (4 bytes LE)`
///     `  nLockTime (4 bytes LE)`
///     `  scriptSig hash (32 bytes, or 0x00..00 if no scriptSig)`
///     `  input count (4 bytes LE)`
///     `  sequences hash (32 bytes)`
///     `  output count (4 bytes LE)`
///     `  outputs hash (32 bytes)`
///     `  input index (4 bytes LE)`
///   `)`
///
/// Any transaction spending a CTV-locked output MUST produce the same hash
/// from its own fields; otherwise the script fails.
///
/// This implementation takes the pre-computed component hashes rather than
/// a full transaction structure so callers can incrementally update the
/// commitment when only part of the template changes.
///
/// # Parameters
/// - `nversion`       — Transaction version (1 or 2; use 2 for relative timelocks).
/// - `nlocktime`      — Absolute locktime (0 = unlocked; or block height / time).
/// - `scriptsig_hash` — SHA-256 of all concatenated scriptSigs; `None` → 32 zero bytes.
/// - `input_count`    — Number of transaction inputs (must match the real tx).
/// - `sequences_hash` — SHA-256 of all input nSequence values concatenated.
/// - `output_count`   — Number of transaction outputs.
/// - `outputs_hash`   — SHA-256 of all serialised outputs (value || scriptPubKey).
/// - `input_index`    — The index of the input containing the CTV opcode.
///
/// Reference: https://github.com/bitcoin/bips/blob/master/bip-0119.mediawiki
pub fn ctv_template_hash(
    nversion:       i32,
    nlocktime:      u32,
    scriptsig_hash: Option<&[u8; 32]>,
    input_count:    u32,
    sequences_hash: &[u8; 32],
    output_count:   u32,
    outputs_hash:   &[u8; 32],
    input_index:    u32,
) -> Hash256 {
    let zero32 = [0u8; 32];
    let sig_hash = scriptsig_hash.unwrap_or(&zero32);

    let mut data = Vec::with_capacity(4 + 4 + 32 + 4 + 32 + 4 + 32 + 4);
    data.extend_from_slice(&nversion.to_le_bytes());
    data.extend_from_slice(&nlocktime.to_le_bytes());
    data.extend_from_slice(sig_hash);
    data.extend_from_slice(&input_count.to_le_bytes());
    data.extend_from_slice(sequences_hash);
    data.extend_from_slice(&output_count.to_le_bytes());
    data.extend_from_slice(outputs_hash);
    data.extend_from_slice(&input_index.to_le_bytes());

    // BIP-119 uses a single SHA-256 (not double-SHA256) for the template hash.
    let digest = Sha256::digest(&data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Hash256(out)
}

/// Compute SHA-256 of all concatenated `nSequence` values.
///
/// Used when building the `sequences_hash` argument for `ctv_template_hash`.
/// Each sequence is serialised as a 4-byte little-endian u32.
pub fn hash_sequences(sequences: &[u32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for seq in sequences {
        hasher.update(&seq.to_le_bytes());
    }
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute SHA-256 of all serialised outputs.
///
/// Each output is serialised as: `value (8 bytes LE) || compact_size(script_len) || script`.
pub fn hash_outputs(outputs: &[(u64, &[u8])]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for (value, script) in outputs {
        hasher.update(&value.to_le_bytes());
        let mut cs = Vec::new();
        push_compact_size(&mut cs, script.len() as u64);
        hasher.update(&cs);
        hasher.update(script);
    }
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Append a Bitcoin compact-size integer to `buf`.
///
/// Compact-size encoding:
///   0..=0xfc       → 1 byte
///   0xfd..=0xffff  → 0xfd || 2 bytes LE
///   0x10000..=0xffff_ffff → 0xfe || 4 bytes LE
///   larger         → 0xff || 8 bytes LE
fn push_compact_size(buf: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => buf.push(n as u8),
        0xfd..=0xffff => {
            buf.push(0xfd);
            buf.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            buf.push(0xfe);
            buf.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            buf.push(0xff);
            buf.extend_from_slice(&n.to_le_bytes());
        }
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256d_empty() {
        // SHA-256d("") is a known value; ensures the double-hash is applied.
        let h = sha256d(b"");
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        // SHA-256 of that = 5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456
        let expected = hex::decode(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        ).unwrap();
        assert_eq!(&h.0[..], expected.as_slice());
    }

    #[test]
    fn tagged_hash_differs_by_tag() {
        let a = tagged_hash("TapLeaf",   b"data");
        let b = tagged_hash("TapBranch", b"data");
        assert_ne!(a, b, "Different tags must produce different hashes");
    }

    #[test]
    fn tapbranch_is_order_independent() {
        let l = Hash256([1u8; 32]);
        let r = Hash256([2u8; 32]);
        assert_eq!(
            tapbranch_hash(&l, &r),
            tapbranch_hash(&r, &l),
            "TapBranch must be commutative (canonical sort)"
        );
    }

    #[test]
    fn compact_size_boundaries() {
        let mut buf = Vec::new();
        push_compact_size(&mut buf, 0xfc);
        assert_eq!(buf, vec![0xfc]);

        buf.clear();
        push_compact_size(&mut buf, 0xfd);
        assert_eq!(buf, vec![0xfd, 0xfd, 0x00]);

        buf.clear();
        push_compact_size(&mut buf, 0x1_0000);
        assert_eq!(buf, vec![0xfe, 0x00, 0x00, 0x01, 0x00]);
    }
}