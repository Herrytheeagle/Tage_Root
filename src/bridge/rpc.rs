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
