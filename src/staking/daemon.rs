// =============================================================================
// src/staking/daemon.rs — Validator Daemon
// =============================================================================
//
// Polls a Bitcoin node for new blocks and distributes sequencing-fee rewards
// to all active validators once per epoch.
//
// Reward source: L2 sequencing fees and restaking revenue (no BTC inflation).
// See research paper §5.3: "Re-staking and security provisioning."

use std::{thread, time::Duration};

use crate::{
    bridge::rpc::BtcRpcClient,
    error::Result,
    staking::validator::ValidatorRegistry,
    types::Amount,
};

// ── Config ────────────────────────────────────────────────────────────────────

/// Runtime configuration for the validator daemon.
#[derive(Debug, Clone)]
pub struct ValidatorDaemonConfig {
    /// Bitcoin Core JSON-RPC endpoint.
    pub rpc_url: String,
    pub rpc_user: String,
    pub rpc_pass: String,
    /// Poll interval in seconds.
    pub poll_interval_secs: u64,
    /// Number of Bitcoin blocks per reward epoch.  Default: 144 (≈ 1 day).
    pub epoch_blocks: u32,
    /// Total satoshis distributed to validators per epoch.
    /// Represents collected sequencing fees for that epoch.
    pub epoch_reward_sats: u64,
}

impl ValidatorDaemonConfig {
    /// Build config from environment variables with sensible defaults.
    ///
    /// | Variable | Default |
    /// |---|---|
    /// | `BITCOIN_RPC_URL` | `http://127.0.0.1:18443` |
    /// | `BITCOIN_RPC_USER` | `bitcoin` |
    /// | `BITCOIN_RPC_PASS` | `bitcoin` |
    /// | `TAGE_POLL_INTERVAL` | `10` seconds |
    /// | `TAGE_EPOCH_BLOCKS` | `144` |
    /// | `TAGE_EPOCH_REWARD_SATS` | `100000` (0.001 BTC) |
    pub fn from_env() -> Self {
        Self {
            rpc_url: std::env::var("BITCOIN_RPC_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:18443".into()),
            rpc_user: std::env::var("BITCOIN_RPC_USER")
                .unwrap_or_else(|_| "bitcoin".into()),
            rpc_pass: std::env::var("BITCOIN_RPC_PASS")
                .unwrap_or_else(|_| "bitcoin".into()),
            poll_interval_secs: std::env::var("TAGE_POLL_INTERVAL")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
            epoch_blocks: std::env::var("TAGE_EPOCH_BLOCKS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(144),
            epoch_reward_sats: std::env::var("TAGE_EPOCH_REWARD_SATS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100_000),
        }
    }
}

// ── Daemon ────────────────────────────────────────────────────────────────────

/// The validator daemon.
///
/// Watches Bitcoin block height and distributes epoch rewards to all
/// active validators, weighted by their bonded BTC.
pub struct ValidatorDaemon {
    config: ValidatorDaemonConfig,
    pub registry: ValidatorRegistry,
    rpc: BtcRpcClient,
    /// The block height at which the last reward epoch was settled.
    last_reward_height: u64,
}

impl ValidatorDaemon {
    /// Create a new validator daemon.
    pub fn new(config: ValidatorDaemonConfig, registry: ValidatorRegistry) -> Result<Self> {
        let rpc = BtcRpcClient::new(&config.rpc_url, &config.rpc_user, &config.rpc_pass)?;
        Ok(Self {
            config,
            registry,
            rpc,
            last_reward_height: 0,
        })
    }

    /// Start the event loop.  Blocks the calling thread.
    pub fn run(&mut self) -> Result<()> {
        let interval = Duration::from_secs(self.config.poll_interval_secs);
        log::info!(
            "Validator daemon started — epoch: {} blocks — reward: {} sats/epoch — {} active validators",
            self.config.epoch_blocks,
            self.config.epoch_reward_sats,
            self.registry.active_count(),
        );

        // Seed last_reward_height from the current tip so we don't
        // retroactively pay out rewards for all historical blocks.
        if let Ok(h) = self.rpc.get_block_count() {
            self.last_reward_height = h;
            log::info!("Starting at block height {} (rewards begin next epoch)", h);
        }

        loop {
            match self.rpc.get_block_count() {
                Ok(height) => self.maybe_distribute(height),
                Err(e) => log::error!("Cannot reach Bitcoin node: {}", e),
            }
            thread::sleep(interval);
        }
    }

    fn maybe_distribute(&mut self, height: u64) {
        let elapsed = height.saturating_sub(self.last_reward_height);
        if elapsed < self.config.epoch_blocks as u64 {
            return;
        }

        // Distribute one reward per full epoch elapsed.
        let epochs = elapsed / self.config.epoch_blocks as u64;
        let total_reward = Amount(self.config.epoch_reward_sats.saturating_mul(epochs));

        match self.registry.distribute_rewards(total_reward) {
            Ok(()) => {
                log::info!(
                    "Epoch reward settled — {} sats across {} validators \
                     (blocks {}–{}, {} epochs)",
                    total_reward.sats(),
                    self.registry.active_count(),
                    self.last_reward_height,
                    height,
                    epochs,
                );
                self.last_reward_height = height;
            }
            Err(e) => log::error!("Reward distribution failed at height {}: {}", height, e),
        }
    }
}
