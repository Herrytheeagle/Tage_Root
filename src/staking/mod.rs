// =============================================================================
// src/staking/mod.rs — Staking Module
// =============================================================================
//
// Validator bonding, reward distribution, and slashing.
// Implements economic security for the L2.

pub mod daemon;
pub mod slashing;
pub mod validator;

// Re-export key types
pub use daemon::*;
pub use slashing::*;
pub use validator::*;
