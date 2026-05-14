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
    println!("Running Tage end-to-end demo...");

    let mut state = L2State::new();
    let mut peg_in = PegInManager::new();
    let mut lending_pool = LendingPool::new(BlockHeight(0));
    let mut peg_out = PegOutManager::new();

    let current_height = BlockHeight(100);
    let deposit_amount = Amount(1_000_000);
    let outpoint = OutPoint {
        txid: TxId([42u8; 32]),
        vout: 0,
    };

    println!("1) Creating peg-in address for L2 recipient 'Heritage'");
    let (peg_script, bridge_template) =
        peg_in.create_peg_address("Heritage", deposit_amount, current_height)?;
    println!(
        "   Peg-in address ready. Deposit amount = {} sats",
        deposit_amount.sats()
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

    println!("3) Confirming deposit and crediting L2");
    let (recipient, amount) = peg_in.confirm_deposit(&outpoint, BlockHeight(106))?;
    println!(
        "   Confirmed deposit for {} with {} sats",
        recipient,
        amount.sats()
    );

    println!("4) Depositing the credited amount into the lending pool");
    lending_pool.deposit("Heritage".into(), amount, BlockHeight(106))?;
    println!(
        "   Lending pool utilisation = {} bps",
        lending_pool.utilisation_bps()
    );

    println!("5) Borrowing from the lending pool against collateral");
    lending_pool.borrow(
        "panda".into(),
        Amount(500_000),
        Amount(750_000),
        BlockHeight(106),
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

    println!("7) Submitting peg-out request for the original deposit");
    let state_proof = state.trie.state_root(); // use real committed state root as proof
    let request = PegOutRequest::new(
        outpoint,
        Amount(500_000),
        XOnlyPubKey([1u8; 32]),
        state_proof,
        BlockHeight(106),
    );
    peg_out.submit_request(request)?;
    println!("   Peg-out request queued");

    println!("8) Finalising peg-out after confirmation depth");
    let final_txid =
        peg_out.finalise_peg_out(&outpoint, BlockHeight(106 + PEG_OUT_CONFIRMATION_DEPTH))?;
    println!("   Peg-out transaction ID = {}", final_txid);

    println!("Demo complete.");
    Ok(())
}
