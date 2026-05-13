// =============================================================================
// src/staking/slashing.rs — Slashing Logic
// =============================================================================
//
// Validator slashing for misbehaviour.
// Implements penalties for fraud proofs and downtime.

use crate::{
    error::{BtcFiError, Result},
    staking::validator::ValidatorRegistry,
    types::{Amount, Hash256, XOnlyPubKey},
};
use serde::{Deserialize, Serialize};

// ── Slashing Conditions ───────────────────────────────────────────────────────

/// Reasons for slashing a validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlashingReason {
    /// Submitted fraudulent bridge claim.
    FraudulentClaim { claim_hash: Hash256 },

    /// Failed to respond to fraud proof challenge.
    ChallengeTimeout { dispute_id: Hash256 },

    /// Validator offline during critical period.
    Downtime { blocks_offline: u32 },
}

// ── Slash Event ───────────────────────────────────────────────────────────────

/// A slashing event against a validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashEvent {
    /// The slashed validator.
    pub validator: XOnlyPubKey,

    /// Reason for slashing.
    pub reason: SlashingReason,

    /// Amount slashed.
    pub slash_amount: Amount,

    /// Block height when slashed.
    pub slashed_at: u32,
}

impl SlashEvent {
    pub fn new(
        validator: XOnlyPubKey,
        reason: SlashingReason,
        slash_amount: Amount,
        height: u32,
    ) -> Self {
        Self {
            validator,
            reason,
            slash_amount,
            slashed_at: height,
        }
    }
}

// ── Slashing Manager ──────────────────────────────────────────────────────────

/// Manages validator slashing.
#[derive(Debug, Default)]
pub struct SlashingManager {
    /// Recorded slash events.
    pub events: Vec<SlashEvent>,
}

impl SlashingManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Slash a validator for misbehaviour.
    pub fn slash_validator(
        &mut self,
        validator: &XOnlyPubKey,
        reason: SlashingReason,
        registry: &mut ValidatorRegistry,
        current_height: u32,
    ) -> Result<Amount> {
        let validator_info = registry
            .get_validator(validator)
            .ok_or(BtcFiError::ValidatorNotFound)?;

        // Calculate slash amount (e.g., 10% of stake)
        let slash_amount = Amount((validator_info.bond.0 * 10) / 100);

        // Remove from active set
        registry.remove_validator(validator)?;

        // Record the event
        let event = SlashEvent::new(*validator, reason, slash_amount, current_height);
        self.events.push(event);

        Ok(slash_amount)
    }

    /// Check if a validator has been slashed.
    pub fn is_slashed(&self, validator: &XOnlyPubKey) -> bool {
        self.events.iter().any(|e| e.validator == *validator)
    }
}
