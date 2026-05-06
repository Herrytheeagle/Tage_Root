// =============================================================================
// src/execution/mod.rs — Execution Module
// =============================================================================
//
// EVM-like L2 state machine for BTCFi.
// Implements L1 of the six-layer framework with Bitcoin-native execution.

pub mod state;
pub mod vm;

// Re-export key types
pub use state::*;
pub use vm::*;