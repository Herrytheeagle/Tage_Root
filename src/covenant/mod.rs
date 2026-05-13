// =============================================================================
// src/covenant/mod.rs — Covenant Module
// =============================================================================
//
// Bitcoin covenants for trust-minimised execution.
// Implements Taproot and CTV enforcement mechanisms.

pub mod ctv;
pub mod taproot;

// Re-export key types
pub use ctv::*;
pub use taproot::*;
