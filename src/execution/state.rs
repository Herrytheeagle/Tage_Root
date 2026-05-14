// =============================================================================
// src/execution/state.rs — L2 State Management
// =============================================================================
//
// Global state trie for shared L2 state across all modules.
// Implements the shared global state required for cross-protocol composability.

use crate::{
    error::Result,
    types::{Address, Hash256, U256},
    utils::hash::sha256d,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufReader, BufWriter},
    path::PathBuf,
};

// ── State Trie ────────────────────────────────────────────────────────────────

/// A simple Merkle trie for L2 state storage.
/// In production, this would be a proper Ethereum-style state trie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTrie {
    /// Root hash of the state trie.
    pub root: Hash256,

    /// Storage slots, keyed by address + slot.
    #[serde(with = "storage_map")]
    storage: HashMap<(Address, U256), U256>,
}

mod storage_map {
    use super::{Address, U256};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;

    #[derive(Serialize, Deserialize)]
    struct Entry((Address, U256), U256);

    pub fn serialize<S>(map: &HashMap<(Address, U256), U256>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let entries: Vec<Entry> = map
            .iter()
            .map(|(key, value)| Entry((key.0, key.1), *value))
            .collect();
        entries.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<(Address, U256), U256>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let entries: Vec<Entry> = Vec::deserialize(deserializer)?;
        Ok(entries.into_iter().map(|Entry(key, value)| (key, value)).collect())
    }
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
        self.storage
            .get(&(*address, *slot))
            .copied()
            .unwrap_or(U256::zero())
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// A generic store interface for durable L2 state persistence.
pub trait StateStore {
    /// Load the latest committed state from durable storage.
    fn load_state(&self) -> Result<L2State>;

    /// Persist the provided state snapshot.
    fn save_state(&self, state: &L2State) -> Result<()>;
}

/// JSON-backed state persistence for prototypes and local testing.
#[derive(Debug, Clone)]
pub struct JsonStateStore {
    path: PathBuf,
}

impl JsonStateStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
        }
    }

    pub fn load(&self) -> Result<L2State> {
        match File::open(&self.path) {
            Ok(file) => {
                let reader = BufReader::new(file);
                let state = serde_json::from_reader(reader)?;
                Ok(state)
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(L2State::new()),
            Err(err) => Err(err.into()),
        }
    }

    pub fn save(&self, state: &L2State) -> Result<()> {
        let file = File::create(&self.path)?;
        let writer = BufWriter::new(file);
        serde_json::to_writer_pretty(writer, state)?;
        Ok(())
    }
}

impl StateStore for JsonStateStore {
    fn load_state(&self) -> Result<L2State> {
        self.load()
    }

    fn save_state(&self, state: &L2State) -> Result<()> {
        self.save(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{env, fs};

    #[test]
    fn json_state_store_roundtrip() {
        let temp_file = env::temp_dir().join(format!(
            "tage_state_store_test_{}.json",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let store = JsonStateStore::new(&temp_file);
        let mut state = L2State::new();
        state.block_height = 42;
        state.write_storage(&Address::zero(), &U256::from_u64(7), U256::from_u64(123));

        store.save(&state).expect("save should succeed");
        let loaded = store.load().expect("load should succeed");

        assert_eq!(loaded.block_height, 42);
        assert_eq!(loaded.read_storage(&Address::zero(), &U256::from_u64(7)), U256::from_u64(123));

        fs::remove_file(&temp_file).ok();
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
