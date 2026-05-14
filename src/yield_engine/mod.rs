// =============================================================================
// src/yield_engine/mod.rs — Yield Engine Module
// =============================================================================
//
// Lending pools, interest rate models, and yield generation.
// Implements DeFi primitives on BTC.

pub mod daemon;
pub mod interest_rate;
pub mod lending_pool;

// Re-export key types
pub use daemon::*;
pub use interest_rate::*;
pub use lending_pool::*;
