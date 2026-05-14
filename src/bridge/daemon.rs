// =============================================================================
// src/bridge/daemon.rs — Bridge Operator Daemon
// =============================================================================
//
// Polls a live Bitcoin Core node to:
//   1. Detect when registered peg-in deposits reach confirmation depth.
//   2. Finalise and broadcast mature peg-out transactions.
//
// Configure via environment variables (see BridgeDaemonConfig::from_env).
// Default endpoint targets Bitcoin Core in regtest mode on localhost.

use std::{thread, time::Duration};

use crate::{
    bridge::{
        peg_in::PegInManager,
        peg_out::{PegOutManager, PEG_OUT_CONFIRMATION_DEPTH},
        rpc::BtcRpcClient,
    },
    error::Result,
    execution::state::L2State,
    types::BlockHeight,
};

// ── Config ────────────────────────────────────────────────────────────────────

/// Runtime configuration for the bridge operator daemon.
#[derive(Debug, Clone)]
pub struct BridgeDaemonConfig {
    /// Bitcoin Core JSON-RPC endpoint, e.g. `http://127.0.0.1:18443` (regtest).
    pub rpc_url: String,
    /// RPC username (as set in `bitcoin.conf` or `-rpcuser`).
    pub rpc_user: String,
    /// RPC password.
    pub rpc_pass: String,
    /// How often to poll the Bitcoin node, in seconds.
    pub poll_interval_secs: u64,
    /// Number of confirmations required before crediting a peg-in on L2.
    pub confirmation_depth: u32,
}

impl BridgeDaemonConfig {
    /// Build config from environment variables with sensible regtest defaults.
    ///
    /// | Variable | Default |
    /// |---|---|
    /// | `BITCOIN_RPC_URL` | `http://127.0.0.1:18443` (regtest port) |
    /// | `BITCOIN_RPC_USER` | `bitcoin` |
    /// | `BITCOIN_RPC_PASS` | `bitcoin` |
    /// | `TAGE_POLL_INTERVAL` | `10` seconds |
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
            confirmation_depth: 6,
        }
    }
}

// ── Daemon ────────────────────────────────────────────────────────────────────

/// The bridge operator daemon.
///
/// Holds the peg-in / peg-out managers and a shared L2 state instance.
/// On every poll tick it:
///   - Scans the Bitcoin UTXO set for registered peg-in scripts.
///   - Confirms deposits that have reached `confirmation_depth`.
///   - Broadcasts any peg-out transactions whose timelock has matured.
pub struct BridgeDaemon {
    config: BridgeDaemonConfig,
    pub peg_in: PegInManager,
    pub peg_out: PegOutManager,
    pub state: L2State,
    rpc: BtcRpcClient,
}

impl BridgeDaemon {
    /// Create a new bridge daemon and establish the RPC connection.
    ///
    /// The connection is lazy — the node does not need to be online at
    /// construction time; the first RPC call will surface any connectivity error.
    pub fn new(
        config: BridgeDaemonConfig,
        peg_in: PegInManager,
        peg_out: PegOutManager,
        state: L2State,
    ) -> Result<Self> {
        let rpc = BtcRpcClient::new(&config.rpc_url, &config.rpc_user, &config.rpc_pass)?;
        Ok(Self { config, peg_in, peg_out, state, rpc })
    }

    /// Start the event loop.  Blocks the calling thread; send SIGINT to stop.
    pub fn run(&mut self) -> Result<()> {
        let interval = Duration::from_secs(self.config.poll_interval_secs);
        log::info!(
            "Bridge daemon started — node: {} — poll: {}s — depth: {} blocks",
            self.config.rpc_url,
            self.config.poll_interval_secs,
            self.config.confirmation_depth,
        );

        loop {
            match self.rpc.get_block_count() {
                Ok(height) => {
                    log::debug!("Tick at block height {}", height);
                    if let Err(e) = self.tick(height) {
                        log::error!("Tick error at height {}: {}", height, e);
                    }
                }
                Err(e) => log::error!("Cannot reach Bitcoin node ({}): {}", self.config.rpc_url, e),
            }
            thread::sleep(interval);
        }
    }

    fn tick(&mut self, current_height: u64) -> Result<()> {
        self.scan_for_deposits(current_height)?;
        self.process_peg_outs(current_height)?;
        Ok(())
    }

    /// Scan the UTXO set for each pending peg-in script.
    /// Confirms any deposit whose UTXO has reached `confirmation_depth`.
    fn scan_for_deposits(&mut self, current_height: u64) -> Result<()> {
        // Snapshot pending deposits so we don't borrow self.peg_in mutably
        // while also calling confirm_deposit on it below.
        let pending: Vec<(crate::types::OutPoint, Vec<u8>, String)> = self
            .peg_in
            .pending_deposits()
            .into_iter()
            .map(|d| (d.outpoint, d.peg_address_script.as_bytes().to_vec(), d.l2_recipient.clone()))
            .collect();

        for (expected_outpoint, script_bytes, recipient) in pending {
            let utxos = match self.rpc.scan_utxos_for_script(&script_bytes) {
                Ok(u) => u,
                Err(e) => {
                    log::warn!("UTXO scan failed for recipient {}: {}", recipient, e);
                    continue;
                }
            };

            for utxo in utxos {
                if utxo.outpoint != expected_outpoint {
                    continue; // different UTXO paying to the same script — not ours
                }

                let confirmations = current_height.saturating_sub(utxo.block_height) + 1;
                if confirmations >= self.config.confirmation_depth as u64 {
                    match self.peg_in.confirm_deposit(
                        &expected_outpoint,
                        BlockHeight(current_height as u32),
                    ) {
                        Ok((rec, amount)) => log::info!(
                            "Deposit CONFIRMED — {} sats credited to {} (outpoint {})",
                            amount.sats(),
                            rec,
                            expected_outpoint,
                        ),
                        Err(e) => log::warn!("confirm_deposit error: {}", e),
                    }
                } else {
                    log::info!(
                        "Deposit pending — outpoint {} — {}/{} confirmations",
                        expected_outpoint,
                        confirmations,
                        self.config.confirmation_depth,
                    );
                }
            }
        }
        Ok(())
    }

    /// Find all mature peg-out requests, build their transactions, finalise
    /// them in the manager, then broadcast to the Bitcoin network.
    fn process_peg_outs(&mut self, current_height: u64) -> Result<()> {
        let mature: Vec<crate::types::OutPoint> = self
            .peg_out
            .pending_requests()
            .into_iter()
            .filter(|r| current_height as u32 >= r.requested_at.0 + PEG_OUT_CONFIRMATION_DEPTH)
            .map(|r| r.deposit_outpoint)
            .collect();

        for outpoint in mature {
            // Build BEFORE finalise_peg_out — finalisation removes the request
            // from the pending map, making build_peg_out_tx unable to find it.
            let tx = match self.peg_out.build_peg_out_tx(&outpoint) {
                Ok(t) => t,
                Err(e) => {
                    log::warn!("Cannot build peg-out tx for {}: {}", outpoint, e);
                    continue;
                }
            };

            match self.peg_out.finalise_peg_out(&outpoint, BlockHeight(current_height as u32)) {
                Ok(local_txid) => {
                    log::info!("Peg-out finalised — local txid: {}", local_txid);
                    // Broadcast. The transaction is unsigned here — on mainnet
                    // a signing step using the bridge operator key must precede
                    // this call. On regtest with `-acceptnonstdtxn` it may succeed.
                    match self.rpc.broadcast_tx(&tx) {
                        Ok(node_txid) => {
                            log::info!("Peg-out broadcast — node txid: {}", node_txid)
                        }
                        Err(e) => log::warn!(
                            "Broadcast rejected (add witness signing for mainnet): {}",
                            e
                        ),
                    }
                }
                Err(e) => log::warn!("Peg-out finalisation failed for {}: {}", outpoint, e),
            }
        }
        Ok(())
    }
}
