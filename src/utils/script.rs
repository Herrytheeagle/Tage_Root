// =============================================================================
// src/utils/script.rs — Bitcoin Script Utilities
// =============================================================================
//
// Helpers for building and parsing Bitcoin scripts.
// Provides safe script construction for covenants and transactions.

use crate::{
    error::{BtcFiError, Result},
    types::{Script, XOnlyPubKey},
};
use bitcoin::opcodes;
use bitcoin::script::Builder;

// ── Script Building ───────────────────────────────────────────────────────────

/// Build a P2TR script for a given public key.
pub fn build_p2tr_script(pubkey: &XOnlyPubKey) -> Result<Script> {
    let pk = bitcoin::key::XOnlyPublicKey::from_slice(&pubkey.0)
        .map_err(|_| BtcFiError::InvalidPublicKey)?;

    let mut script = Vec::with_capacity(34);
    script.push(0x51); // OP_1
    script.push(0x20); // push 32 bytes
    script.extend_from_slice(&pk.serialize());

    Ok(Script(script))
}

/// Build a CTV template script.
pub fn build_ctv_script(template_hash: &[u8; 32]) -> Result<Script> {
    let mut script = Vec::with_capacity(34);
    script.push(0x20); // push 32 bytes
    script.extend_from_slice(template_hash);
    script.push(0xBA); // OP_CHECKTEMPLATEVERIFY

    Ok(Script(script))
}

/// Build a multi-signature script.
pub fn build_multisig_script(threshold: u8, pubkeys: &[XOnlyPubKey]) -> Result<Script> {
    if threshold as usize > pubkeys.len() {
        return Err(BtcFiError::InvalidMultisigParams);
    }

    let mut builder = Builder::new().push_int(threshold as i64);

    for pk in pubkeys {
        let pk_bytes = bitcoin::key::XOnlyPublicKey::from_slice(&pk.0)
            .map_err(|_| BtcFiError::InvalidPublicKey)?;
        builder = builder.push_slice(&pk_bytes.serialize());
    }

    let script = builder
        .push_int(pubkeys.len() as i64)
        .push_opcode(opcodes::all::OP_CHECKMULTISIG)
        .into_script();

    Ok(Script(script.into_bytes()))
}

// ── Script Parsing ────────────────────────────────────────────────────────────

/// Parse a script to extract the public key from P2TR.
pub fn parse_p2tr_script(script: &Script) -> Result<XOnlyPubKey> {
    let _bitcoin_script = bitcoin::Script::from_bytes(&script.0);
    // TODO: Parse P2TR script
    // Placeholder
    Ok(XOnlyPubKey([0u8; 32]))
}

/// Validate a script for correctness.
pub fn validate_script(script: &Script) -> Result<()> {
    let _bitcoin_script = bitcoin::Script::from_bytes(&script.0);
    // Basic validation
    if script.0.is_empty() {
        return Err(BtcFiError::InvalidScript);
    }
    Ok(())
}
