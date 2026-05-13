// =============================================================================
// src/execution/state.rs — L2 State Management
// =============================================================================
//
// Global state trie for shared L2 state across all modules.
// Implements the shared global state required for cross-protocol composability.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::{
    error::Result,
    types::{Address, Hash256, U256},
    utils::hash::sha256d,
};

// ── State Trie ────────────────────────────────────────────────────────────────

/// A simple Merkle trie for L2 state storage.
/// In production, this would be a proper Ethereum-style state trie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTrie {
    /// Root hash of the state trie.
    pub root: Hash256,

    /// Storage slots, keyed by address + slot.
    storage: HashMap<(Address, U256), U256>,
}

impl StateTrie {
    pub fn new() -> Self {
        Self {
            root: Hash256([0u8; 32]),
            storage: HashMap::new(),
        }
    }

    /// Read a storage slot.
    pub fn get(&self, address: &Address, slot: &U256) -> U256 {
        self.storage.get(&(*address, *slot)).copied().unwrap_or(U256::zero())
    }

    /// Write a storage slot.
    pub fn set(&mut self, address: &Address, slot: &U256, value: U256) {
        self.storage.insert((*address, *slot), value);
        self.update_root();
    }

    /// Update the root hash after state changes.
    fn update_root(&mut self) {
        // Simple hash of all storage for now
        let mut data = Vec::new();
        for ((addr, slot), value) in &self.storage {
            data.extend_from_slice(&addr.0);
            data.extend_from_slice(&slot.to_bytes_be());
            data.extend_from_slice(&value.to_bytes_be());
        }
        self.root = sha256d(&data);
    }

    /// Get the current state root.
    pub fn state_root(&self) -> Hash256 {
        self.root
    }
}

impl Default for StateTrie {
    fn default() -> Self {
        Self::new()
    }
}

// ── L2 State ──────────────────────────────────────────────────────────────────

/// Global L2 state shared across all modules.
#[derive(Debug)]
pub struct L2State {
    /// Global state trie.
    pub trie: StateTrie,

    /// Current block height.
    pub block_height: u64,

    /// Pending transactions.
    pub pending_txs: Vec<L2Transaction>,
}

impl L2State {
    pub fn new() -> Self {
        Self {
            trie: StateTrie::new(),
            block_height: 0,
            pending_txs: Vec::new(),
        }
    }

    /// Read a storage slot from the shared L2 state trie.
    pub fn read_storage(&self, address: &Address, slot: &U256) -> U256 {
        self.trie.get(address, slot)
    }

    /// Write a storage slot into the shared L2 state trie.
    pub fn write_storage(&mut self, address: &Address, slot: &U256, value: U256) {
        self.trie.set(address, slot, value);
    }

    /// Apply a transaction to the state.
    pub fn apply_transaction(&mut self, tx: L2Transaction) -> Result<()> {
        // TODO: Execute transaction logic
        // For now, just add to pending
        self.pending_txs.push(tx);
        Ok(())
    }

    /// Finalise the current block.
    pub fn finalise_block(&mut self) {
        self.block_height += 1;
        self.pending_txs.clear();
        // Update trie root
        self.trie.update_root();
    }
}

impl Default for L2State {
    fn default() -> Self {
        Self::new()
    }
}

// ── L2 Transaction ────────────────────────────────────────────────────────────

/// A transaction in the L2 state machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2Transaction {
    pub from: Address,
    pub to: Address,
    pub value: U256,
    pub data: Vec<u8>,
    pub nonce: u64,
}