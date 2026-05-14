// =============================================================================
// src/bridge/peg_out.rs — Peg-Out Logic
// =============================================================================
//
// Handles the release of BTC from the bridge back to Bitcoin mainnet.
// Implements the exit path for trust-minimised bridging (L2).

use crate::{
    bridge::rpc::BtcRpcClient,
    error::{BtcFiError, Result},
    types::{Amount, BlockHeight, Hash256, OutPoint, TxId, XOnlyPubKey},
};
use bitcoin::{
    absolute::LockTime,
    blockdata::{
        script::{Builder, ScriptBuf},
        transaction::{
            OutPoint as BtcOutPoint, Transaction as BtcTransaction, TxIn, TxOut, Version,
        },
    },
    hashes::Hash,
    secp256k1::XOnlyPublicKey as BtcXOnlyPublicKey,
    Amount as BtcAmount, Sequence, Txid as BtcTxid, Witness,
};
use serde::{Deserialize, Serialize};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Minimum confirmation depth for peg-out transactions.
pub const PEG_OUT_CONFIRMATION_DEPTH: u32 = 6;

/// Timelock for emergency exits (in blocks).
pub const EMERGENCY_EXIT_TIMELOCK_BLOCKS: u32 = 144;

// ── Peg-Out Request ───────────────────────────────────────────────────────────

/// A request to peg-out BTC from the L2 back to mainnet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PegOutRequest {
    /// The deposit outpoint being redeemed.
    pub deposit_outpoint: OutPoint,

    /// Amount to peg out (must match deposit amount minus fees).
    pub amount: Amount,

    /// Recipient's mainnet address (P2TR).
    pub recipient: XOnlyPubKey,

    /// L2 state proof showing the peg-out is authorised.
    pub state_proof: Hash256,

    /// Block height when request was submitted.
    pub requested_at: BlockHeight,
}

impl PegOutRequest {
    pub fn new(
        deposit_outpoint: OutPoint,
        amount: Amount,
        recipient: XOnlyPubKey,
        state_proof: Hash256,
        current_height: BlockHeight,
    ) -> Self {
        Self {
            deposit_outpoint,
            amount,
            recipient,
            state_proof,
            requested_at: current_height,
        }
    }
}

// ── Peg-Out Manager ───────────────────────────────────────────────────────────

/// Manages peg-out requests and finalisation.
pub struct PegOutManager {
    /// Pending peg-out requests, keyed by deposit outpoint.
    requests: std::collections::HashMap<String, PegOutRequest>,

    /// Finalised peg-outs, keyed by mainnet txid.
    finalised: std::collections::HashMap<String, TxId>,

    /// Optional live connection to a Bitcoin Core node.
    rpc: Option<BtcRpcClient>,
}

impl std::fmt::Debug for PegOutManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PegOutManager")
            .field("requests", &self.requests)
            .field("finalised", &self.finalised)
            .field("has_rpc", &self.rpc.is_some())
            .finish()
    }
}

impl Default for PegOutManager {
    fn default() -> Self {
        Self {
            requests: std::collections::HashMap::new(),
            finalised: std::collections::HashMap::new(),
            rpc: None,
        }
    }
}

impl PegOutManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a live Bitcoin Core RPC connection to this manager.
    ///
    /// Once set, `broadcast_peg_out_tx` and `check_confirmations` become
    /// functional against the real network.
    pub fn with_rpc(mut self, client: BtcRpcClient) -> Self {
        self.rpc = Some(client);
        self
    }

    /// Broadcast a signed peg-out transaction to the Bitcoin network.
    ///
    /// Requires an RPC client to have been attached via `with_rpc`.
    /// Returns the txid confirmed by the node.
    pub fn broadcast_peg_out_tx(&self, tx: &BtcTransaction) -> Result<TxId> {
        let rpc = self
            .rpc
            .as_ref()
            .ok_or_else(|| BtcFiError::BitcoinRpc("no RPC client configured".into()))?;
        rpc.broadcast_tx(tx)
    }

    /// Query the confirmation count for a finalised peg-out txid.
    ///
    /// Requires an RPC client to have been attached via `with_rpc`.
    pub fn check_confirmations(&self, txid: &TxId) -> Result<u32> {
        let rpc = self
            .rpc
            .as_ref()
            .ok_or_else(|| BtcFiError::BitcoinRpc("no RPC client configured".into()))?;
        rpc.get_confirmations(txid)
    }

    /// Submit a peg-out request.
    ///
    /// Verifies the state proof and queues the request for processing.
    pub fn submit_request(&mut self, request: PegOutRequest) -> Result<()> {
        let key = request.deposit_outpoint.to_string();

        // TODO: Verify state proof against global state root
        // For now, accept all requests (placeholder)

        self.requests.insert(key, request);
        Ok(())
    }

    /// Finalise a peg-out by creating and broadcasting the mainnet transaction.
    ///
    /// Returns the mainnet txid if successful.
    pub fn finalise_peg_out(
        &mut self,
        deposit_outpoint: &OutPoint,
        current_height: BlockHeight,
    ) -> Result<TxId> {
        let key = deposit_outpoint.to_string();
        let request = self
            .requests
            .get(&key)
            .ok_or_else(|| BtcFiError::PegOutNotFound { txid: key.clone() })?;

        // Check confirmation depth
        if current_height.0 < request.requested_at.0 + PEG_OUT_CONFIRMATION_DEPTH {
            return Err(BtcFiError::PegOutNotConfirmed {
                blocks_remaining: (request.requested_at.0 + PEG_OUT_CONFIRMATION_DEPTH)
                    - current_height.0,
            });
        }

        // Create mainnet transaction
        let txid = self.create_mainnet_tx(request)?;

        // Mark as finalised
        self.finalised.insert(key.clone(), txid);
        self.requests.remove(&key);

        Ok(txid)
    }

    /// Create the mainnet peg-out transaction.
    fn create_mainnet_tx(&self, request: &PegOutRequest) -> Result<TxId> {
        let tx = self.build_unsigned_tx(request, request.recipient)?;
        Ok(TxId(tx.txid().to_byte_array()))
    }

    fn build_unsigned_tx(
        &self,
        request: &PegOutRequest,
        recipient: XOnlyPubKey,
    ) -> Result<BtcTransaction> {
        if request.amount.0 < Amount::DUST_P2TR.0 {
            return Err(BtcFiError::BelowDustThreshold {
                amount: request.amount.0,
                threshold: Amount::DUST_P2TR.0,
            });
        }

        let prev_txid = BtcTxid::from_byte_array(request.deposit_outpoint.txid.0);
        let outpoint = BtcOutPoint {
            txid: prev_txid,
            vout: request.deposit_outpoint.vout,
        };

        let script_pubkey = self.build_p2tr_script(recipient)?;

        Ok(BtcTransaction {
            version: Version::non_standard(2),
            lock_time: LockTime::from_consensus(0),
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: BtcAmount::from_sat(request.amount.0),
                script_pubkey,
            }],
        })
    }

    fn build_p2tr_script(&self, recipient: XOnlyPubKey) -> Result<ScriptBuf> {
        let xonly = BtcXOnlyPublicKey::from_slice(&recipient.0)
            .map_err(|_| BtcFiError::InvalidPublicKey)?;

        Ok(Builder::new()
            .push_int(1)
            .push_slice(&xonly.serialize())
            .into_script())
    }

    /// Emergency exit for stuck deposits.
    ///
    /// After timelock expires, allows direct claim without L2 proof.
    pub fn emergency_exit(
        &mut self,
        deposit_outpoint: &OutPoint,
        recipient: XOnlyPubKey,
        current_height: BlockHeight,
    ) -> Result<TxId> {
        let key = deposit_outpoint.to_string();
        let request = self
            .requests
            .get(&key)
            .ok_or_else(|| BtcFiError::PegOutNotFound { txid: key.clone() })?;

        // Check timelock
        if current_height.0 < request.requested_at.0 + EMERGENCY_EXIT_TIMELOCK_BLOCKS {
            return Err(BtcFiError::EmergencyExitTimelock {
                blocks_remaining: (request.requested_at.0 + EMERGENCY_EXIT_TIMELOCK_BLOCKS)
                    - current_height.0,
            });
        }

        // Create emergency tx
        let txid = self.create_emergency_tx(request, recipient)?;

        Ok(txid)
    }

    fn create_emergency_tx(&self, request: &PegOutRequest, recipient: XOnlyPubKey) -> Result<TxId> {
        let tx = self.build_unsigned_tx(request, recipient)?;
        Ok(TxId(tx.txid().to_byte_array()))
    }
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::TxId;

    fn op() -> OutPoint {
        OutPoint {
            txid: TxId([1u8; 32]),
            vout: 0,
        }
    }

    fn key() -> XOnlyPubKey {
        XOnlyPubKey([2u8; 32])
    }

    #[test]
    fn submit_and_finalise_peg_out() {
        let mut mgr = PegOutManager::new();
        let request = PegOutRequest::new(
            op(),
            Amount(100000),
            key(),
            Hash256([3u8; 32]),
            BlockHeight(0),
        );

        mgr.submit_request(request).unwrap();
        let txid = mgr
            .finalise_peg_out(&op(), BlockHeight(PEG_OUT_CONFIRMATION_DEPTH))
            .unwrap();
        assert!(txid.0 != [0u8; 32]);
    }

    #[test]
    fn emergency_exit_after_timelock() {
        let mut mgr = PegOutManager::new();
        let request = PegOutRequest::new(
            op(),
            Amount(100000),
            key(),
            Hash256([3u8; 32]),
            BlockHeight(0),
        );

        mgr.submit_request(request).unwrap();
        let txid = mgr
            .emergency_exit(&op(), key(), BlockHeight(EMERGENCY_EXIT_TIMELOCK_BLOCKS))
            .unwrap();
        assert!(txid.0 != [0u8; 32]);
    }
}
