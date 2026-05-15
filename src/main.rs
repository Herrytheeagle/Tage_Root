// =============================================================================
// src/main.rs — Tage CLI and Daemon
// =============================================================================
//
// Command-line interface and daemon for running Tage nodes.
// Supports bridge operator, validator, and yield engine roles.

use std::env;
use tage::bridge::daemon::{BridgeDaemon, BridgeDaemonConfig};
use tage::bridge::peg_in::PegInManager;
use tage::bridge::peg_out::{PegOutManager, PegOutRequest, PEG_OUT_CONFIRMATION_DEPTH};
use tage::bridge::rpc::BtcRpcClient;
use tage::error::Result;
use tage::execution::state::L2State;
use tage::staking::daemon::{ValidatorDaemon, ValidatorDaemonConfig};
use tage::staking::validator::ValidatorRegistry;
use tage::types::{Amount, BlockHeight, OutPoint, TxId, XOnlyPubKey};
use tage::yield_engine::daemon::{YieldDaemon, YieldDaemonConfig};
use tage::yield_engine::lending_pool::LendingPool;

fn main() -> Result<()> {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <command>", args[0]);
        eprintln!("Commands: bridge, validator, yield, --demo");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "bridge" => run_bridge_operator(),
        "validator" => run_validator(),
        "yield" => run_yield_engine(),
        "--demo" => run_demo(),
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            std::process::exit(1);
        }
    }
}

fn run_bridge_operator() -> Result<()> {
    let config = BridgeDaemonConfig::from_env();
    println!("Starting Tage Bridge Operator");
    println!("  RPC endpoint : {}", config.rpc_url);
    println!("  Poll interval: {}s", config.poll_interval_secs);
    println!("  Confirm depth: {} blocks", config.confirmation_depth);
    println!("  Set BITCOIN_RPC_URL / BITCOIN_RPC_USER / BITCOIN_RPC_PASS to override.");
    println!();

    let mut daemon = BridgeDaemon::new(
        config,
        PegInManager::new(),
        PegOutManager::new(),
        L2State::new(),
    )?;
    daemon.run()
}

fn run_validator() -> Result<()> {
    let config = ValidatorDaemonConfig::from_env();
    println!("Starting Tage Validator Daemon");
    println!("  RPC endpoint  : {}", config.rpc_url);
    println!("  Epoch length  : {} blocks (~{} hours)", config.epoch_blocks, config.epoch_blocks / 6);
    println!("  Epoch reward  : {} sats", config.epoch_reward_sats);
    println!("  Set TAGE_EPOCH_BLOCKS / TAGE_EPOCH_REWARD_SATS to override.");
    println!();

    let mut daemon = ValidatorDaemon::new(config, ValidatorRegistry::new())?;
    daemon.run()
}

fn run_yield_engine() -> Result<()> {
    let config = YieldDaemonConfig::from_env();
    println!("Starting Tage Yield Engine Daemon");
    println!("  RPC endpoint : {}", config.rpc_url);
    println!("  Poll interval: {}s", config.poll_interval_secs);
    println!("  Set BITCOIN_RPC_URL / BITCOIN_RPC_USER / BITCOIN_RPC_PASS to override.");
    println!();

    let mut daemon = YieldDaemon::new(
        config,
        LendingPool::new(BlockHeight(0)),
        L2State::new(),
    )?;
    daemon.run()
}
fn run_demo() -> Result<()> {
    println!("Running Tage end-to-end demo (live regtest node)...");

    // ── Connect to the live Bitcoin Core regtest node ─────────────────────────
    let rpc_url = std::env::var("BITCOIN_RPC_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18443".into());
    let rpc_user = std::env::var("BITCOIN_RPC_USER")
        .unwrap_or_else(|_| "heritage".into());
    let rpc_pass = std::env::var("BITCOIN_RPC_PASS")
        .unwrap_or_else(|_| "tageroot2024".into());

    let rpc = BtcRpcClient::new(&rpc_url, &rpc_user, &rpc_pass)?;
    let chain_tip = rpc.get_block_count()?;
    println!("Connected to Bitcoin Core at {}", rpc_url);
    println!("Chain tip  : block {}", chain_tip);
    println!();

    // Derive demo block heights from the live chain tip.
    let current_height  = BlockHeight(chain_tip as u32);
    let confirm_height  = BlockHeight(chain_tip as u32 + 6);
    let finalise_height = BlockHeight(chain_tip as u32 + 6 + PEG_OUT_CONFIRMATION_DEPTH);

    let mut state        = L2State::new();
    let mut peg_in       = PegInManager::new();
    let mut lending_pool = LendingPool::new(current_height);
    let mut peg_out      = PegOutManager::new().with_rpc(rpc);

    let deposit_amount = Amount(1_000_000);
    let outpoint = OutPoint {
        txid: TxId([42u8; 32]),
        vout: 0,
    };

    println!("1) Creating peg-in address for L2 recipient 'Heritage'");
    let (peg_script, bridge_template) =
        peg_in.create_peg_address("Heritage", deposit_amount, current_height)?;
    println!(
        "   Peg-in address ready. Deposit = {} sats  (height {})",
        deposit_amount.sats(),
        current_height.0,
    );

    println!("2) Registering deposit in bridge state and shared L2 trie");
    peg_in.register_deposit(
        &mut state,
        outpoint,
        deposit_amount,
        String::from("Heritage"),
        peg_script,
        bridge_template,
    )?;
    println!("   Deposit recorded with outpoint {}", outpoint);
    println!(
        "   Shared state root after deposit = {}",
        state.trie.state_root()
    );

    println!("3) Confirming deposit and crediting L2  (simulated +6 blocks → height {})", confirm_height.0);
    let (recipient, amount) = peg_in.confirm_deposit(&outpoint, confirm_height)?;
    println!(
        "   Confirmed deposit for {} with {} sats",
        recipient,
        amount.sats()
    );

    println!("4) Depositing the credited amount into the lending pool");
    lending_pool.deposit("Heritage".into(), amount, confirm_height)?;
    println!(
        "   Lending pool utilisation = {} bps",
        lending_pool.utilisation_bps()
    );

    println!("5) Borrowing from the lending pool against collateral");
    lending_pool.borrow(
        "panda".into(),
        Amount(500_000),
        Amount(750_000),
        confirm_height,
    )?;
    println!(
        "   Borrow succeeded; utilisation = {} bps",
        lending_pool.utilisation_bps()
    );

    println!("6) Persisting pool totals to shared state trie");
    lending_pool.persist_totals_to_state(&mut state);
    println!(
        "   Shared state root after pool update = {}",
        state.trie.state_root()
    );

    println!("7) Submitting peg-out request");
    let state_proof = state.trie.state_root();
    let request = PegOutRequest::new(
        outpoint,
        Amount(500_000),
        XOnlyPubKey([1u8; 32]),
        state_proof,
        confirm_height,
    );
    peg_out.submit_request(request)?;
    println!("   Peg-out request queued  (state root = {})", state_proof);

    println!("8) Building peg-out Bitcoin transaction");
    let tx = peg_out.build_peg_out_tx(&outpoint)?;
    println!(
        "   Transaction built — {} input(s), {} output(s)",
        tx.input.len(),
        tx.output.len()
    );

    println!("9) Finalising peg-out  (simulated height {})", finalise_height.0);
    let final_txid = peg_out.finalise_peg_out(&outpoint, finalise_height)?;
    println!("   Local peg-out txid = {}", final_txid);

    println!("10) Broadcasting transaction to regtest node at {}", rpc_url);
    match peg_out.broadcast_peg_out_tx(&tx) {
        Ok(node_txid) => println!("    Broadcast accepted — node txid: {}", node_txid),
        Err(e) => println!(
            "    Broadcast rejected (unsigned demo tx — expected on regtest): {}",
            e
        ),
    }

    println!();
    println!("Demo complete.");
    Ok(())
}
