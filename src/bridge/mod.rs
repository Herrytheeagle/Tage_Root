// =============================================================================
// src/bridge/mod.rs — Bridge Module
// =============================================================================
//
// Trust-minimised BTC bridging with CTV and BitVM fallbacks.
// Implements L2 of the six-layer framework.

pub mod bitvm_bridge;
pub mod peg_in;
pub mod peg_out;
pub mod rpc;

// Re-export key types
pub use bitvm_bridge::*;
pub use peg_in::*;
pub use peg_out::*;
pub use rpc::*;
