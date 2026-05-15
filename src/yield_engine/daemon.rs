// =============================================================================
// src/yield_engine/daemon.rs — Yield Engine Daemon
// =============================================================================
//
// Polls a Bitcoin node for new blocks and, on each block advance:
//   - Accrues interest on all open borrow positions.
//   - Persists updated pool totals to the shared L2 state trie.
//   - Logs pool metrics every N blocks.
//
// Interest accrual is the source of yield for all lenders.  Without this
// daemon running, the pool's exchange rate would not increase over time.

use std::{thread, time::Duration};

use crate::{
    bridge::rpc::BtcRpcClient,
    error::Result,
    execution::state::L2State,
    types::BlockHeight,
    yield_engine::lending_pool::LendingPool,
};

// ── Config ────────────────────────────────────────────────────────────────────

/// Runtime configuration for the yield engine daemon.
#[derive(Debug, Clone)]
pub struct YieldDaemonConfig {
    /// Bitcoin Core JSON-RPC endpoint.
    pub rpc_url: String,
    pub rpc_user: String,
    pub rpc_pass: String,
    /// Poll interval in seconds.
    pub poll_interval_secs: u64,
    /// Print pool metrics to the log every this many blocks.
    pub metrics_log_interval_blocks: u32,
}

impl YieldDaemonConfig {
    /// Build config from environment variables with sensible defaults.
    ///
    /// | Variable | Default |
    /// |---|---|
    /// | `BITCOIN_RPC_URL` | `http://127.0.0.1:18443` |
    /// | `BITCOIN_RPC_USER` | `bitcoin` |
    /// | `BITCOIN_RPC_PASS` | `bitcoin` |
    /// | `TAGE_POLL_INTERVAL` | `10` seconds |
    pub fn from_env() -> Self {
        Self {
            rpc_url: std::env::var("BITCOIN_RPC_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:18443".into()),
            rpc_user: std::env::var("BITCOIN_RPC_USER")
                .unwrap_or_else(|_| "heritage".into()),
            rpc_pass: std::env::var("BITCOIN_RPC_PASS")
                .unwrap_or_else(|_| "tageroot2024".into()),
            poll_interval_secs: std::env::var("TAGE_POLL_INTERVAL")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
            metrics_log_interval_blocks: 10,
        }
    }
}

// ── Daemon ────────────────────────────────────────────────────────────────────

/// The yield engine daemon.
///
/// Drives interest accrual on every new Bitcoin block and keeps the
/// shared L2 state trie up to date with the latest pool totals.
pub struct YieldDaemon {
    config: YieldDaemonConfig,
    pub pool: LendingPool,
    pub state: L2State,
    rpc: BtcRpcClient,
    last_height: u64,
}

impl YieldDaemon {
    /// Create a new yield daemon.
    pub fn new(
        config: YieldDaemonConfig,
        pool: LendingPool,
        state: L2State,
    ) -> Result<Self> {
        let rpc = BtcRpcClient::new(&config.rpc_url, &config.rpc_user, &config.rpc_pass)?;
        Ok(Self { config, pool, state, rpc, last_height: 0 })
    }

    /// Start the event loop.  Blocks the calling thread.
    pub fn run(&mut self) -> Result<()> {
        let interval = Duration::from_secs(self.config.poll_interval_secs);
        log::info!(
            "Yield engine daemon started — node: {} — poll: {}s",
            self.config.rpc_url,
            self.config.poll_interval_secs,
        );

        // Seed last_height from the current tip so we accrue from now,
        // not from the genesis block.
        match self.rpc.get_block_count() {
            Ok(h) => {
                self.last_height = h;
                log::info!("Starting at block height {}", h);
            }
            Err(e) => log::warn!("Could not fetch initial block height: {}", e),
        }

        loop {
            match self.rpc.get_block_count() {
                Ok(height) => {
                    if height > self.last_height {
                        self.on_new_blocks(height);
                        self.last_height = height;
                    }
                }
                Err(e) => log::error!("Cannot reach Bitcoin node: {}", e),
            }
            thread::sleep(interval);
        }
    }

    fn on_new_blocks(&mut self, height: u64) {
        let new_height = BlockHeight(height as u32);
        self.pool.accrue_interest(new_height);
        self.pool.persist_totals_to_state(&mut self.state);

        if height % self.config.metrics_log_interval_blocks as u64 == 0 {
            let m = self.pool.metrics();
            log::info!(
                "Pool @ block {} — deposits: {} sats  borrows: {} sats  \
                 util: {} bps  borrow_rate: {} bps APR  supply_rate: {} bps APR",
                height,
                m.total_deposits.sats(),
                m.total_borrows.sats(),
                m.utilisation_bps,
                m.borrow_rate_bps,
                m.supply_rate_bps,
            );
        }
    }
}
