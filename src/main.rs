// =============================================================================
// src/main.rs — Tage CLI and Daemon
// =============================================================================
//
// Command-line interface and daemon for running Tage nodes.
// Supports bridge operator, validator, and yield engine roles.

use std::env;
use tage::error::Result;

fn main() -> Result<()> {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <command>", args[0]);
        eprintln!("Commands: bridge, validator, yield");
        std::process::exit(1);
    }

    match args[1].as_str() {
        "bridge" => run_bridge_operator(),
        "validator" => run_validator(),
        "yield" => run_yield_engine(),
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            std::process::exit(1);
        }
    }
}

fn run_bridge_operator() -> Result<()> {
    println!("Starting Tage Bridge Operator...");
    // TODO: Implement bridge operator daemon
    Ok(())
}

fn run_validator() -> Result<()> {
    println!("Starting Tage Validator...");
    // TODO: Implement validator daemon
    Ok(())
}

fn run_yield_engine() -> Result<()> {
    println!("Starting Tage Yield Engine...");
    // TODO: Implement yield engine daemon
    Ok(())
}