// =============================================================================
// src/error.rs — Unified Error Type
// =============================================================================
//
// All modules in this crate return `BtcFiError` so call-sites can use the `?`
// operator uniformly without wrapping multiple error enums.
//
// References
// ----------
// None (standard Rust error-handling pattern using `thiserror`).

use thiserror::Error;

/// The single error type exported by this crate.
///
/// Each variant documents the subsystem that raised it and, where applicable,
/// references the BIP or protocol concept that the failing operation relates to.
#[derive(Debug, Error)]
pub enum BtcFiError {
    // ── Covenant / BIP-119 ────────────────────────────────────────────────────
    /// Raised when a CTV template hash does not match the spending transaction.
    ///
    /// See: BIP-119 §"Template Hash" — the commitment is the SHA-256 of a
    /// serialised template that encodes output count, sequences, outputs, and
    /// the input index.  Any deviation must be rejected.
    #[error("CTV template mismatch: expected {expected}, got {got}")]
    CtvTemplateMismatch { expected: String, got: String },

    /// A script being built would exceed Bitcoin's 10,000-byte limit.
    #[error("Script too large: {size} bytes (max 10,000)")]
    ScriptTooLarge { size: usize },

    // ── Taproot / BIP-340 / BIP-341 ──────────────────────────────────────────
    /// The Taproot internal key supplied is not a valid secp256k1 x-only pubkey.
    ///
    /// See: BIP-340 §"Public Key Format" — only 32-byte x-only keys are valid
    /// for Taproot key-path and script-path spending.
    #[error("Invalid Taproot internal key: {reason}")]
    InvalidTaprootKey { reason: String },

    /// Taproot script tree depth exceeds the 128-level limit from BIP-341.
    #[error("Taproot tree depth {depth} exceeds maximum of 128")]
    TaprootTreeTooDeep { depth: usize },

    // ── Bridge ────────────────────────────────────────────────────────────────
    /// The amount supplied for a peg-in or peg-out is below the minimum dust
    /// threshold (546 satoshis for P2TR outputs as per Bitcoin Core policy).
    #[error("Amount {amount} sats is below dust threshold {threshold} sats")]
    BelowDustThreshold { amount: u64, threshold: u64 },

    /// A peg-out request references a deposit that does not exist in the bridge
    /// state.
    #[error("Deposit not found: {txid}")]
    DepositNotFound { txid: String },

    /// The timelock on a peg-out has not expired yet.
    ///
    /// The unilateral-exit timelock is a core safety property — users must wait
    /// for the challenge window before they can force-exit without the sequencer.
    #[error("Timelock not expired: current block {current}, unlock at {unlock}")]
    TimelockNotExpired { current: u32, unlock: u32 },

    // ── BitVM / Optimistic Bridge (Path B) ───────────────────────────────────
    /// The fraud proof submitted during a BitVM challenge round does not
    /// falsify the prover's claim at the bisected step.
    #[error("BitVM fraud proof invalid at step {step}: {reason}")]
    BitvmFraudProofInvalid { step: u32, reason: String },

    /// The BitVM challenge window has expired; the prover's claim is now final.
    #[error("BitVM challenge window expired at block {block}")]
    BitvmChallengeWindowExpired { block: u32 },

    // ── Execution Layer ───────────────────────────────────────────────────────
    /// A contract execution ran out of gas before completing.
    #[error("Contract execution out of gas: used {used}, limit {limit}")]
    OutOfGas { used: u64, limit: u64 },

    /// A state-transition was rejected because the state root in the proposal
    /// does not match the current committed root.
    #[error("State root mismatch: expected {expected}, got {got}")]
    StateRootMismatch { expected: String, got: String },

    // ── Yield Engine ─────────────────────────────────────────────────────────
    /// A withdrawal from the lending pool was requested but the pool is
    /// currently under-liquid (utilisation at 100%).
    #[error("Insufficient pool liquidity: requested {requested}, available {available}")]
    InsufficientLiquidity { requested: u64, available: u64 },

    /// A borrow request exceeds the collateral factor for the supplied
    /// collateral amount.
    #[error("Collateral insufficient: need {required} sats, have {supplied} sats")]
    InsufficientCollateral { required: u64, supplied: u64 },

    // ── Staking ───────────────────────────────────────────────────────────────
    /// A validator attempted to register but the bond amount is below the
    /// minimum required to participate in consensus.
    #[error("Bond too small: minimum is {minimum} sats, got {got} sats")]
    BondTooSmall { minimum: u64, got: u64 },

    /// A slashing proof references a validator that is not registered.
    #[error("Unknown validator: {pubkey}")]
    UnknownValidator { pubkey: String },

    // ── Execution / VM ────────────────────────────────────────────────────────
    #[error("VM stack underflow")]
    VmStackUnderflow,

    #[error("VM invalid opcode: {opcode}")]
    VmInvalidOpcode { opcode: u8 },

    #[error("VM invalid jump destination: {dest}")]
    VmInvalidJumpDestination { dest: usize },

    #[error("VM division by zero")]
    VmDivisionByZero,

    #[error("VM memory out of bounds")]
    VmMemoryOutOfBounds,

    // ── Peg-out ───────────────────────────────────────────────────────────────
    #[error("Peg-out not found: {txid}")]
    PegOutNotFound { txid: String },

    #[error("Peg-out not confirmed: {blocks_remaining} blocks remaining")]
    PegOutNotConfirmed { blocks_remaining: u32 },

    #[error("Emergency exit timelock: {blocks_remaining} blocks remaining")]
    EmergencyExitTimelock { blocks_remaining: u32 },

    // ── Validator ─────────────────────────────────────────────────────────────
    #[error("Validator not found")]
    ValidatorNotFound,

    // ── Script ────────────────────────────────────────────────────────────────
    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid multisig parameters")]
    InvalidMultisigParams,

    #[error("Invalid script")]
    InvalidScript,

    // ── General ───────────────────────────────────────────────────────────────
    /// Wraps any standard I/O errors (file loading, socket reads, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Wraps hex-decode failures on script and hash inputs.
    #[error("Hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    /// Wraps JSON (de)serialisation failures for state persistence.
    #[error("State store JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Wraps Bitcoin RPC errors (node connectivity, broadcast failures, etc.).
    #[error("Bitcoin RPC error: {0}")]
    BitcoinRpc(String),
}

/// Convenience alias used throughout the crate.
pub type Result<T> = std::result::Result<T, BtcFiError>;
