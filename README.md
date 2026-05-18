# Tage_Root
TAGE: SOLUTION TO BRIDGE PROBLEM AND THE PRICING OF BITCOIN-DENOMINATED YIELD. 

Bitcoin's base layer was designed for settlement finality, not programmable finance. Its UTXO model, constrained scripting language, and deliberate absence of native smart contract execution have made it the most secure and decentralised monetary network in existence and simultaneously the least capable of natively generating yield or supporting staking mechanics. This paper investigates the structural reasons why Bitcoin-denominated yield cannot be trustlessly produced on-chain at Layer 1, characterises the trust assumptions embedded in existing off-chain solutions, and proposes a framework for a trust-minimised Layer 2 execution environment capable of supporting staking, lending, and yield generation while preserving Bitcoin's security guarantees. We reference relevant Bitcoin Improvement Proposals (BIPs)  including BIP-340, BIP-341, BIP-342, BIP-119, and the prospective BIP-300/301 as architectural primitives for such a system, and conclude with a recommended implementation path for a BTCFi Layer 2 stack called Tage.

Key terms : BTCFi, Tage, Bitcoin yield, staking, Layer 2, trust-minimised bridge, BIP-119, Taproot, OP_CTV, BitVM, covenant scripting 


**Trust-Minimised Execution Infrastructure in BTCFi 

> Reference implementation for the architecture proposed in:
> *"The Bridge Problem and the Pricing of Bitcoin-Denominated Yield:
> Investigating Trust-Minimised Execution Infrastructure in BTCFi"*
> — BTCFi Research Series, Paper 1 (2025)

---

## Overview

This repository contains a Rust reference implementation of the trust-minimised
Layer 2 execution stack described in the Tage research paper. It covers:

| Module            | Description                                                      |
|-------------------|------------------------------------------------------------------|
| `bridge`          | Peg-in / peg-out logic; CTV-enforced and BitVM optimistic paths  |
| `covenant`        | OP_CTV (BIP-119) template construction and verification          |
| `execution`       | Lightweight EVM-like execution layer for yield contracts         |
| `yield_engine`    | Lending pool, interest rate curves, and reward distribution      |
| `staking`         | Validator bonding, slashing conditions, and reward accounting    |
| `utils`           | Script encoding, TXID hashing, Taproot (BIP-340/341) helpers     |

---

## Why This Exists

Bitcoin's base layer was deliberately designed for settlement finality, not
programmable finance. Its UTXO model and constrained scripting language make
native staking and yield generation architecturally impossible without protocol
extensions.

Every Bitcoin yield product that exists today introduces trust assumptions —
centralised custodians (wBTC), threshold-signature committees (tBTC), or
opaque lending books (CeFi exchanges). This codebase implements the trust-
minimised alternative: Tage, a Layer 2 where yield is generated through genuine
economic activity and users can always exit unilaterally.

---

## Relevant Bitcoin Improvement Proposals

| BIP       | Title                                        | Status       | Relevance                                      |
|-----------|----------------------------------------------|--------------|------------------------------------------------|
| BIP-340   | Schnorr Signatures for secp256k1             | Active       | Key aggregation, MuSig2 signing                |
| BIP-341   | Taproot (SegWit v1 spending rules)           | Active       | Multi-path UTXOs, Tapscript trees              |
| BIP-342   | Validation of Taproot Scripts                | Active       | New opcodes, Tapscript execution rules         |
| BIP-119   | OP_CHECKTEMPLATEVERIFY (CTV)                 | Proposed     | Covenant peg construction (Path A)             |
| BIP-118   | SIGHASH_ANYPREVOUT                           | Proposed     | Output rebinding, channel factories            |
| BIP-300   | Hashrate Escrows (Drivechains)               | Proposed     | Sidechain peg alternative                      |
| BIP-301   | Blind Merged Mining                          | Proposed     | Sidechain security via merge-mining            |

---

## Two Deployment Paths

### Path A — With OP_CTV (BIP-119 activated)
The peg mechanism is implemented as native Tapscript with CTV commitments.
No off-chain prover infrastructure is required. Exit guarantees are enforced
at the Bitcoin script level. This is the preferred production path.

### Path B — BitVM Optimistic Verification (BIP-119 not yet activated)
The peg mechanism uses BitVM-style pre-signed transaction trees with an
optimistic fraud-proof protocol. Deployable on mainnet today. Requires an
online challenger and a liquidity provider layer to cover exit delays.

---

## Repository Structure

```
tage/
├── Cargo.toml
├── README.md
├── LICENSE
├── src/
│   ├── main.rs                  # Entry point and CLI demo
│   ├── lib.rs                   # Crate root, module declarations
│   ├── types.rs                 # Shared types: Amount, TxId, Script, etc.
│   ├── error.rs                 # Unified error type
│   ├── bridge/
│   │   ├── mod.rs               # Bridge module root
│   │   ├── peg_in.rs            # Peg-in: lock BTC → mint L2 position
│   │   ├── peg_out.rs           # Peg-out: burn L2 position → unlock BTC
│   │   ├── bitvm_bridge.rs      # Path B: BitVM optimistic bridge
│   │   ├── daemon.rs            # Bridge operator daemon (polls Bitcoin Core)
│   │   └── rpc.rs               # Bitcoin RPC client wrapper
│   ├── covenant/
│   │   ├── mod.rs               # Covenant module root
│   │   ├── ctv.rs               # BIP-119 CTV template construction
│   │   └── taproot.rs           # BIP-340/341 Taproot helpers
│   ├── execution/
│   │   ├── mod.rs               # Execution layer root
│   │   ├── vm.rs                # Lightweight contract VM
│   │   └── state.rs             # L2 state root and transitions
│   ├── yield_engine/
│   │   ├── mod.rs               # Yield engine root
│   │   ├── lending_pool.rs      # BTC lending / borrowing pool
│   │   ├── interest_rate.rs     # Utilisation-based rate curves
│   │   └── daemon.rs            # Yield engine daemon (polls Bitcoin Core)
│   ├── staking/
│   │   ├── mod.rs               # Staking module root
│   │   ├── validator.rs         # Validator registration and bonding
│   │   ├── slashing.rs          # Slashing conditions and execution
│   │   └── daemon.rs            # Validator daemon (distributes sequencing rewards)
│   └── utils/
│       ├── mod.rs               # Utils root
│       ├── script.rs            # Bitcoin script encoding helpers
│       └── hash.rs              # SHA-256d, RIPEMD-160, tagged hashes
```

---

## Quick Start

```bash
git clone https://github.com/Herrytheeagle/Tage_Root
cd tage
cargo build
cargo test
cargo run
```

---

## Disclaimer

This is a **research and reference implementation**. It is not production-ready
and has not been audited. Do not use it to manage real Bitcoin funds without a
full independent security review.

---

## License

MIT — see [LICENSE](LICENSE).