// =============================================================================
// src/types.rs — Shared Domain Types
// =============================================================================
//
// All modules share these fundamental types so that function signatures are
// consistent and conversions are explicit.
//
// Design notes
// ------------
// * `Amount` wraps `u64` (satoshis) rather than floating-point to avoid
//   rounding errors in financial arithmetic.  Bitcoin amounts are always
//   integers at the protocol level.
// * `TxId` is a 32-byte array stored in internal byte order (little-endian
//   as used inside Bitcoin transactions), not display order (big-endian).
// * `Script` is an opaque byte vector.  Higher-level builders in
//   `utils::script` produce Scripts from typed inputs.

use serde::{Deserialize, Serialize};
use std::fmt;

// ── Amount ────────────────────────────────────────────────────────────────────

/// A Bitcoin amount denominated in satoshis (1 BTC = 100,000,000 satoshis).
///
/// Arithmetic is checked to prevent overflow/underflow on release builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Amount(pub u64);

impl Amount {
    /// The minimum non-dust amount for a P2TR output (546 sat per Bitcoin Core
    /// policy at a 3 sat/vbyte dust relay rate with a 43-byte output size).
    pub const DUST_P2TR: Self = Self(546);

    /// 1 BTC expressed in satoshis.
    pub const ONE_BTC: Self = Self(100_000_000);

    /// Checked addition — returns `None` on overflow.
    #[inline]
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(Self)
    }

    /// Checked subtraction — returns `None` on underflow.
    #[inline]
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.0.checked_sub(rhs.0).map(Self)
    }

    /// Multiply by a basis-point rate (1 bp = 0.01 %).
    ///
    /// Used by the yield engine for interest accrual:
    ///   `amount.apply_bps(50)` → 0.50 % of amount.
    pub fn apply_bps(self, basis_points: u64) -> Self {
        Self(self.0 * basis_points / 10_000)
    }

    /// Raw satoshi value.
    #[inline]
    pub fn sats(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} sats", self.0)
    }
}

// ── TxId ──────────────────────────────────────────────────────────────────────

/// A 256-bit transaction identifier stored in internal (little-endian) byte order.
///
/// To display as the familiar big-endian hex string (as seen in block explorers),
/// call `.display()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TxId(pub [u8; 32]);

impl TxId {
    /// Returns the TxId bytes reversed for human-readable display (block-explorer
    /// order, which is big-endian).
    pub fn display_hex(&self) -> String {
        let mut rev = self.0;
        rev.reverse();
        hex::encode(rev)
    }

    /// Zero TxId — used as a sentinel / null value.
    pub const ZERO: Self = Self([0u8; 32]);
}

impl fmt::Display for TxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_hex())
    }
}

// ── BlockHeight ───────────────────────────────────────────────────────────────

/// An absolute Bitcoin block height.
///
/// Used for timelock calculations.  CSV (BIP-112) and CLTV (BIP-65) both use
/// block heights as their primary timelock unit for our purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BlockHeight(pub u32);

impl BlockHeight {
    /// Check whether `self` is at or past `target` (i.e. timelock satisfied).
    #[inline]
    pub fn is_past(self, target: Self) -> bool {
        self >= target
    }

    /// Add a number of blocks (e.g. a relative timelock delta).
    #[inline]
    pub fn add_blocks(self, n: u32) -> Self {
        Self(self.0 + n)
    }
}

impl fmt::Display for BlockHeight {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "block {}", self.0)
    }
}

// ── Script ────────────────────────────────────────────────────────────────────

/// An opaque Bitcoin locking or unlocking script (serialised byte vector).
///
/// Use `utils::script::ScriptBuilder` to construct Scripts from typed inputs
/// rather than manipulating raw bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Script(pub Vec<u8>);

impl Script {
    pub fn empty() -> Self {
        Self(Vec::new())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Script {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

// ── XOnlyPubKey ──────────────────────────────────────────────────────────────

/// A 32-byte x-only secp256k1 public key as defined in BIP-340.
///
/// BIP-340 §"Public Key Format":
///   "We encode the public key as the 32-byte encoding of its x-coordinate.
///    This is sufficient for signing/verification since the curve equation
///    determines the y-coordinate up to a parity bit."
///
/// In Taproot (BIP-341) all internal keys and leaf keys are x-only pubkeys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct XOnlyPubKey(pub [u8; 32]);

impl fmt::Display for XOnlyPubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

// ── Hash256 ───────────────────────────────────────────────────────────────────

/// A generic 32-byte hash.  Used for CTV template hashes, Taproot tweak
/// hashes, state roots, and tagged hashes (BIP-340 §"Tagged Hashes").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    pub const ZERO: Self = Self([0u8; 32]);

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

// ── Address ───────────────────────────────────────────────────────────────────

/// An L2 address (20 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address(pub [u8; 20]);

impl Address {
    pub fn zero() -> Self {
        Address([0u8; 20])
    }
}

// ── OutPoint ──────────────────────────────────────────────────────────────────

/// A reference to a specific output within a transaction.
///
/// Every UTXO in Bitcoin is uniquely identified by the (TxId, vout) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OutPoint {
    pub txid: TxId,
    pub vout: u32,
}

impl fmt::Display for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

// ── TxOutput ──────────────────────────────────────────────────────────────────

/// A transaction output: value + locking script.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxOutput {
    pub value: Amount,
    pub script: Script,
}

// ── U256 ─────────────────────────────────────────────────────────────────────

/// A 256-bit unsigned integer for L2 arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct U256(pub [u8; 32]);

impl U256 {
    pub fn zero() -> Self {
        U256([0u8; 32])
    }

    pub fn one() -> Self {
        let mut bytes = [0u8; 32];
        bytes[31] = 1;
        U256(bytes)
    }

    pub fn from_u64(value: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&value.to_be_bytes());
        U256(bytes)
    }

    pub fn as_u64(&self) -> u64 {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.0[24..32]);
        u64::from_be_bytes(bytes)
    }

    pub fn as_usize(&self) -> usize {
        // Convert last 8 bytes to usize
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&self.0[24..32]);
        usize::from_be_bytes(bytes)
    }

    pub fn to_bytes_be(&self) -> [u8; 32] {
        let mut bytes = self.0;
        bytes.reverse(); // Convert to big-endian
        bytes
    }
}

// ── U256 arithmetic helpers ───────────────────────────────────────────────────
//
// U256 bytes are big-endian: self.0[0] is the most significant byte.
// Limbs are little-endian order: limb[0] = least-significant 64 bits (bytes 24..32).

fn u256_to_limbs(x: [u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        let start = (3 - i) * 8;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&x[start..start + 8]);
        limbs[i] = u64::from_be_bytes(buf);
    }
    limbs
}

fn u256_from_limbs(limbs: [u64; 4]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for i in 0..4 {
        let start = (3 - i) * 8;
        bytes[start..start + 8].copy_from_slice(&limbs[i].to_be_bytes());
    }
    bytes
}

fn u256_shl1(x: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (x[i] << 1) | if i + 1 < 32 { x[i + 1] >> 7 } else { 0 };
    }
    out
}

fn u256_get_bit(x: &[u8; 32], bit: usize) -> bool {
    (x[31 - bit / 8] >> (bit % 8)) & 1 == 1
}

fn u256_set_bit(x: &mut [u8; 32], bit: usize) {
    x[31 - bit / 8] |= 1 << (bit % 8);
}

impl std::ops::Add for U256 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let a = u256_to_limbs(self.0);
        let b = u256_to_limbs(rhs.0);
        let mut result = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let (s1, c1) = a[i].overflowing_add(b[i]);
            let (s2, c2) = s1.overflowing_add(carry);
            result[i] = s2;
            carry = c1 as u64 + c2 as u64;
        }
        U256(u256_from_limbs(result))
    }
}

impl std::ops::Sub for U256 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        let a = u256_to_limbs(self.0);
        let b = u256_to_limbs(rhs.0);
        let mut result = [0u64; 4];
        let mut borrow = 0u64;
        for i in 0..4 {
            let (d1, b1) = a[i].overflowing_sub(b[i]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            result[i] = d2;
            borrow = b1 as u64 + b2 as u64;
        }
        U256(u256_from_limbs(result))
    }
}

impl std::ops::Mul for U256 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        let a = u256_to_limbs(self.0);
        let b = u256_to_limbs(rhs.0);
        let mut result = [0u64; 4];
        for i in 0..4 {
            let mut carry: u128 = 0;
            for j in 0..(4 - i) {
                let idx = i + j;
                let prod = (a[i] as u128) * (b[j] as u128)
                    + result[idx] as u128
                    + carry;
                result[idx] = prod as u64;
                carry = prod >> 64;
            }
        }
        U256(u256_from_limbs(result))
    }
}

impl std::ops::Div for U256 {
    type Output = Self;
    fn div(self, rhs: Self) -> Self {
        if rhs == U256::zero() {
            return U256::zero(); // VM op_div checks for zero before delegating here
        }
        let mut quotient = [0u8; 32];
        let mut remainder = U256::zero();
        for bit in (0..256).rev() {
            let mut rem = u256_shl1(remainder.0);
            if u256_get_bit(&self.0, bit) {
                rem[31] |= 1;
            }
            remainder = U256(rem);
            if remainder >= rhs {
                remainder = remainder - rhs;
                u256_set_bit(&mut quotient, bit);
            }
        }
        U256(quotient)
    }
}

// ── DepositStatus ─────────────────────────────────────────────────────────────

/// Tracks the lifecycle state of a bridge deposit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DepositStatus {
    /// BTC has been sent to the peg address; waiting for confirmation.
    Pending,
    /// Deposit confirmed; L2 credit has been minted.
    Confirmed,
    /// User has initiated a peg-out; timelock running.
    PegOutInitiated { unlock_height: BlockHeight },
    /// Peg-out complete; BTC returned to user.
    Redeemed,
}
