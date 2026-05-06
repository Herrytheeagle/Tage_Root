// =============================================================================
// src/lib.rs — Tage Root Library
// =============================================================================
//
// Trust-minimised BTCFi Layer 2 execution infrastructure.
// Implements the six-layer framework: L1 Bitcoin-native execution, L2 bridging,
// L3 intent routing, L4 autonomous allocation, L5 ZK compliance, L6 governance.
//
// This library provides the core modules for:
// - Bridge: Peg-in/out with CTV and BitVM fallbacks
// - Covenant: Taproot and CTV enforcement
// - Execution: EVM-like L2 state machine
// - Staking: Validator bonding and slashing
// - Yield Engine: Lending pools and interest models
// - Utils: Cryptographic primitives and script helpers

pub mod bridge;
pub mod covenant;
pub mod error;
pub mod execution;
pub mod staking;
pub mod types;
pub mod utils;
pub mod yield_engine;

// Re-export key types for convenience
pub use types::*;
pub use error::*;