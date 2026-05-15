// =============================================================================
// src/bridge/rpc.rs — Bitcoin RPC client wrapper
// =============================================================================
//
// Thin wrapper around `bitcoincore-rpc` that exposes only the two operations
// the bridge actually needs: broadcast a signed transaction and query its
// confirmation depth.  All bitcoincore_rpc errors are mapped to
// `BtcFiError::BitcoinRpc` so callers stay on the single-error-type path.

use bitcoin::{
    consensus::encode::serialize,
    hashes::Hash,
    Transaction as BtcTransaction,
    Txid as BtcTxid,
};
use bitcoincore_rpc::{json, Auth, Client, RpcApi};

use crate::{
    error::{BtcFiError, Result},
    types::{Amount, OutPoint, TxId},
};

// ── ScannedUtxo ───────────────────────────────────────────────────────────────

/// A UTXO returned by a `scantxoutset` query.
#[derive(Debug, Clone)]
pub struct ScannedUtxo {
    /// The on-chain outpoint (txid:vout).
    pub outpoint: OutPoint,
    /// Value of the UTXO in satoshis.
    pub amount: Amount,
    /// Block height at which this UTXO was created.
    pub block_height: u64,
}

// ── Client ────────────────────────────────────────────────────────────────────

/// A live connection to a Bitcoin Core node over JSON-RPC.
pub struct BtcRpcClient {
    inner: Client,
}

impl std::fmt::Debug for BtcRpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BtcRpcClient").finish_non_exhaustive()
    }
}

impl BtcRpcClient {
    /// Connect to a Bitcoin Core node using HTTP Basic authentication.
    ///
    /// `url` should include the scheme and port, e.g. `"http://127.0.0.1:8332"`.
    pub fn new(url: &str, user: impl Into<String>, pass: impl Into<String>) -> Result<Self> {
        let auth = Auth::UserPass(user.into(), pass.into());
        let inner =
            Client::new(url, auth).map_err(|e| BtcFiError::BitcoinRpc(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Broadcast a signed transaction to the network via `sendrawtransaction`.
    ///
    /// Returns the txid as reported by the node (which will match the locally
    /// computed txid for a validly serialised transaction).
    pub fn broadcast_tx(&self, tx: &BtcTransaction) -> Result<TxId> {
        let raw = serialize(tx);
        let txid: BtcTxid = self
            .inner
            .send_raw_transaction(raw.as_slice())
            .map_err(|e| BtcFiError::BitcoinRpc(e.to_string()))?;
        Ok(TxId(txid.to_byte_array()))
    }

    /// Return the current chain tip block height via `getblockcount`.
    pub fn get_block_count(&self) -> Result<u64> {
        self.inner
            .get_block_count()
            .map_err(|e| BtcFiError::BitcoinRpc(e.to_string()))
    }

    /// Scan the live UTXO set for all outputs that pay to `script_bytes`.
    ///
    /// Uses Bitcoin Core's `scantxoutset` RPC with a `raw(...)` descriptor.
    /// Returns every unspent output currently paying to that exact script.
    pub fn scan_utxos_for_script(&self, script_bytes: &[u8]) -> Result<Vec<ScannedUtxo>> {
        let descriptor = format!("raw({})", hex::encode(script_bytes));
        let result = self
            .inner
            .scan_tx_out_set_blocking(&[json::ScanTxOutRequest::Single(descriptor)])
            .map_err(|e| BtcFiError::BitcoinRpc(e.to_string()))?;

        Ok(result
            .unspents
            .into_iter()
            .map(|u| ScannedUtxo {
                outpoint: OutPoint {
                    txid: TxId(u.txid.to_byte_array()),
                    vout: u.vout,
                },
                amount: Amount(u.amount.to_sat()),
                block_height: u.height,
            })
            .collect())
    }

    /// Return the number of confirmations for `txid` via `getrawtransaction`.
    ///
    /// Returns `0` if the transaction is in the mempool but not yet mined.
    /// Returns an error if the node has never seen the transaction.
    pub fn get_confirmations(&self, txid: &TxId) -> Result<u32> {
        let btc_txid = BtcTxid::from_byte_array(txid.0);
        let info = self
            .inner
            .get_raw_transaction_info(&btc_txid, None)
            .map_err(|e| BtcFiError::BitcoinRpc(e.to_string()))?;
        Ok(info.confirmations.unwrap_or(0))
    }
}

// =============================================================================
// Integration tests — require a live Bitcoin Core regtest node.
//
// Start node:
//   bitcoind -regtest -rpcuser=heritage -rpcpassword=tageroot2024 -rpcport=18443 \
//            -txindex=1 -daemon
//   bitcoin-cli -regtest -rpcuser=heritage -rpcpassword=tageroot2024 \
//            -rpcport=18443 createwallet tage
//   bitcoin-cli -regtest -rpcuser=heritage -rpcpassword=tageroot2024 \
//            -rpcport=18443 -generate 101
//
// Run with:  cargo test -- --ignored
// =============================================================================
#[cfg(test)]
mod integration {
    use super::*;

    fn regtest_client() -> BtcRpcClient {
        BtcRpcClient::new("http://127.0.0.1:18443", "heritage", "tageroot2024")
            .expect("connect to regtest node — start bitcoind first (see comment above)")
    }

    #[test]
    #[ignore = "requires live regtest node at 127.0.0.1:18443"]
    fn regtest_get_block_count() {
        let rpc = regtest_client();
        let height = rpc.get_block_count().unwrap();
        assert!(
            height >= 101,
            "need at least 101 blocks — run: bitcoin-cli -regtest -generate 101"
        );
        println!("regtest chain tip: block {}", height);
    }

    #[test]
    #[ignore = "requires live regtest node at 127.0.0.1:18443"]
    fn regtest_scan_unused_script_is_empty() {
        let rpc = regtest_client();
        // P2TR script paying to an all-0xff 32-byte key — never funded on a fresh regtest chain.
        let mut script = vec![0x51u8, 0x20];
        script.extend_from_slice(&[0xffu8; 32]);
        let utxos = rpc.scan_utxos_for_script(&script).unwrap();
        assert!(
            utxos.is_empty(),
            "expected no UTXOs for an unused key; found {}",
            utxos.len()
        );
    }

    #[test]
    #[ignore = "requires live regtest node at 127.0.0.1:18443"]
    fn regtest_broadcast_rejects_invalid_tx() {
        use bitcoin::{
            transaction::Version, Amount as BtcAmount, OutPoint as BtcOutPoint,
            ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
        };

        let rpc = regtest_client();
        // An empty-input transaction is always rejected by the node.
        let bad_tx = Transaction {
            version: Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: BtcOutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: BtcAmount::from_sat(0),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let result = rpc.broadcast_tx(&bad_tx);
        assert!(
            result.is_err(),
            "node should reject an invalid transaction"
        );
        println!("broadcast correctly rejected: {}", result.unwrap_err());
    }
}
