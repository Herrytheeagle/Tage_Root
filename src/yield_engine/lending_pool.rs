// =============================================================================
// src/yield_engine/lending_pool.rs — BTC Lending Pool
// =============================================================================
//
// Implements a utilisation-based BTC lending and borrowing pool.
//
// Economic design
// ---------------
// The core insight from the research paper (§2.3, §5.3) is that Bitcoin yield
// is NOT inflationary.  Every basis point of BTC yield must come from a real
// economic source.  In this pool, the source is:
//
//   Borrower interest payments → flow to → Lenders (depositors)
//
// The interest rate is a function of utilisation U = borrowed / deposited:
//
//   Base rate:     r0 = RATE_AT_ZERO_UTIL (e.g. 0.50% APR in basis points)
//   Optimal rate:  r* = RATE_AT_OPTIMAL_UTIL (e.g. 5% APR)
//   Max rate:      rM = RATE_AT_MAX_UTIL (e.g. 100% APR)
//
//   If U <= OPTIMAL_UTILISATION:
//     borrow_rate = r0 + U / U* * (r* - r0)
//   If U > OPTIMAL_UTILISATION:
//     borrow_rate = r* + (U - U*) / (1 - U*) * (rM - r*)
//
// This two-slope model (identical to Aave v2's model) ensures that the rate
// jumps sharply above U* to incentivise liquidity during high demand while
// staying low enough to attract borrowers at normal utilisation.
//
// All rates are in annual basis points (1 bp = 0.01 % per year).
// Per-block accrual converts APR to a per-block rate assuming 144 blocks/day.
//
// References
// ----------
// Research paper §5.3: "Yield Generation Mechanics"
// Aave v2 interest rate model: https://docs.aave.com/risk/liquidity-risk/borrow-interest-rate

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::{
    error::{BtcFiError, Result},
    types::{Amount, BlockHeight},
    yield_engine::interest_rate::*,
};

// ── Position ──────────────────────────────────────────────────────────────────

/// A lender's share of the pool.
///
/// Rather than tracking an exact BTC balance, we track the number of "pool
/// shares" the lender holds.  Shares appreciate in value as interest accrues.
/// This is the same cToken / aToken pattern used by Compound / Aave.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LenderPosition {
    pub l2_address:      String,
    /// Number of pool shares owned by this lender.
    pub shares:          u64,
    /// Block at which this position was last updated.
    pub last_update:     BlockHeight,
}

/// An outstanding borrow from the pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BorrowPosition {
    pub l2_address:      String,
    /// Principal borrowed (satoshis at the time of borrowing).
    pub principal:       Amount,
    /// Accrued interest as of `last_update` (satoshis).
    pub accrued_interest: Amount,
    /// Borrow rate at origination (annual basis points).
    pub borrow_rate_bps: u64,
    /// Block at which interest was last compounded.
    pub last_update:     BlockHeight,
    /// Collateral provided (satoshis; must stay above `COLLATERAL_FACTOR * debt`).
    pub collateral:      Amount,
}

impl BorrowPosition {
    /// Compute the total debt (principal + accrued interest).
    pub fn total_debt(&self) -> Option<Amount> {
        self.principal.checked_add(self.accrued_interest)
    }
}

// ── LendingPool ───────────────────────────────────────────────────────────────

/// A BTC lending pool that allows depositors to earn yield from borrowers.
///
/// # Key invariants
/// 1. `total_deposits >= total_borrows` — borrowers can never exceed the pool.
/// 2. `exchange_rate` is monotonically non-decreasing — lenders never lose
///    principal through pool mechanics (credit losses aside).
/// 3. The pool holds no native token — all accounting is in BTC (satoshis).
#[derive(Debug)]
pub struct LendingPool {
    /// Total BTC deposited (includes lent-out BTC).  Satoshis.
    total_deposits:   u64,

    /// Total BTC currently outstanding to borrowers.  Satoshis.
    total_borrows:    u64,

    /// Total pool shares issued.  Exchange rate = total_deposits / total_shares.
    total_shares:     u64,

    /// Block at which the pool state was last updated.
    last_update:      BlockHeight,

    /// Lender positions.
    lenders:          HashMap<String, LenderPosition>,

    /// Borrow positions.
    borrowers:        HashMap<String, BorrowPosition>,
}

impl LendingPool {
    /// Create an empty pool.
    pub fn new(genesis_height: BlockHeight) -> Self {
        Self {
            total_deposits: 0,
            total_borrows:  0,
            total_shares:   0,
            last_update:    genesis_height,
            lenders:        HashMap::new(),
            borrowers:      HashMap::new(),
        }
    }

    // ── Interest rate model ─────────────────────────────────────────────────

    /// Current utilisation ratio in basis points.
    ///
    /// Utilisation U = total_borrows / total_deposits (clamped to [0, 10_000]).
    pub fn utilisation_bps(&self) -> u64 {
        utilisation_bps(self.total_borrows, self.total_deposits)
    }

    /// Current borrow rate in annual basis points, derived from the two-slope
    /// interest rate model described in the module header.
    pub fn borrow_rate_bps(&self) -> u64 {
        borrow_rate_bps(self.utilisation_bps())
    }

    /// Current supply (deposit) rate in annual basis points.
    ///
    /// Supply rate = borrow_rate * utilisation — the pool distributes borrower
    /// interest proportionally to the share of capital that is deployed.
    pub fn supply_rate_bps(&self) -> u64 {
        supply_rate_bps(self.borrow_rate_bps(), self.utilisation_bps())
    }

    // ── Deposits ────────────────────────────────────────────────────────────

    /// Exchange rate: satoshis per share.
    ///
    /// Starts at 1_000_000_000 (1 BTC per share) and rises as interest accrues.
    fn exchange_rate(&self) -> u64 {
        if self.total_shares == 0 {
            return 1_000_000; // 1 sat per share initially (scaled ×1e6)
        }
        // exchange_rate = total_deposits * 1e6 / total_shares
        self.total_deposits * 1_000_000 / self.total_shares
    }

    /// Deposit BTC into the pool and receive shares.
    ///
    /// # Arguments
    /// * `depositor`      — L2 address of the depositor.
    /// * `amount`         — Amount of BTC to deposit (satoshis).
    /// * `current_height` — Current block height.
    ///
    /// # Returns
    /// The number of pool shares minted to the depositor.
    pub fn deposit(
        &mut self,
        depositor:      String,
        amount:         Amount,
        current_height: BlockHeight,
    ) -> Result<u64> {
        self.accrue_interest(current_height);

        let sats   = amount.sats();
        let rate   = self.exchange_rate();
        // shares = (sats * 1e6) / exchange_rate
        let shares = sats * 1_000_000 / rate;

        self.total_deposits += sats;
        self.total_shares   += shares;

        let pos = self.lenders.entry(depositor.clone()).or_insert(LenderPosition {
            l2_address:  depositor,
            shares:      0,
            last_update: current_height,
        });
        pos.shares      += shares;
        pos.last_update  = current_height;

        log::info!("Deposited {} sats → {} shares", sats, shares);
        Ok(shares)
    }

    /// Withdraw BTC from the pool by redeeming shares.
    ///
    /// # Returns
    /// The BTC amount returned to the depositor.
    pub fn withdraw(
        &mut self,
        depositor:      &str,
        shares:          u64,
        current_height:  BlockHeight,
    ) -> Result<Amount> {
        self.accrue_interest(current_height);

        let rate     = self.exchange_rate();
        let sats_out = shares * rate / 1_000_000;

        let pos = self.lenders.get_mut(depositor)
            .ok_or_else(|| BtcFiError::DepositNotFound { txid: depositor.into() })?;

        if pos.shares < shares {
            return Err(BtcFiError::InsufficientLiquidity {
                requested: shares,
                available: pos.shares,
            });
        }

        // Check the pool has enough liquid BTC (not all lent out).
        let available = self.total_deposits - self.total_borrows;
        if sats_out > available {
            return Err(BtcFiError::InsufficientLiquidity {
                requested: sats_out,
                available,
            });
        }

        pos.shares      -= shares;
        pos.last_update  = current_height;
        self.total_deposits -= sats_out;
        self.total_shares   -= shares;

        log::info!("Withdrew {} sats (redeemed {} shares)", sats_out, shares);
        Ok(Amount(sats_out))
    }

    // ── Borrows ─────────────────────────────────────────────────────────────

    /// Borrow BTC from the pool against collateral.
    ///
    /// The collateral factor is 150%: borrowers must provide 1.5× the borrowed
    /// value in collateral.
    ///
    /// Research paper §5.3:
    ///   "BTC lending and borrowing: Users can deposit BTC into a lending pool
    ///    and earn yield from borrowers who pay interest."
    pub fn borrow(
        &mut self,
        borrower:       String,
        amount:         Amount,
        collateral:     Amount,
        current_height: BlockHeight,
    ) -> Result<()> {
        self.accrue_interest(current_height);

        let min_collateral = amount.sats() * 15_000 / 10_000; // 150% collateral factor
        if collateral.sats() < min_collateral {
            return Err(BtcFiError::InsufficientCollateral {
                required: min_collateral,
                supplied: collateral.sats(),
            });
        }

        let available = self.total_deposits - self.total_borrows;
        if amount.sats() > available {
            return Err(BtcFiError::InsufficientLiquidity {
                requested: amount.sats(),
                available,
            });
        }

        let rate = self.borrow_rate_bps();
        self.total_borrows += amount.sats();

        self.borrowers.insert(borrower.clone(), BorrowPosition {
            l2_address:       borrower,
            principal:        amount,
            accrued_interest: Amount(0),
            borrow_rate_bps:  rate,
            last_update:      current_height,
            collateral,
        });

        Ok(())
    }

    /// Repay a borrow position (partial or full).
    pub fn repay(
        &mut self,
        borrower:       &str,
        amount:         Amount,
        current_height: BlockHeight,
    ) -> Result<Amount> {
        self.accrue_interest(current_height);

        let pos = self.borrowers.get_mut(borrower)
            .ok_or_else(|| BtcFiError::DepositNotFound { txid: borrower.into() })?;

        let total = pos.total_debt().unwrap_or(Amount(u64::MAX));
        let payment = amount.sats().min(total.sats());
        let remaining_sats = total.sats() - payment;

        // Apply payment to interest first, then principal.
        let interest_paid = payment.min(pos.accrued_interest.sats());
        let principal_paid = payment - interest_paid;

        pos.accrued_interest = Amount(pos.accrued_interest.sats() - interest_paid);
        pos.principal        = pos.principal.checked_sub(Amount(principal_paid))
                                    .unwrap_or(Amount(0));
        pos.last_update      = current_height;

        let actual_payment = Amount(payment);
        self.total_borrows   = self.total_borrows.saturating_sub(principal_paid);
        self.total_deposits += interest_paid; // interest flows to depositors

        log::info!("Repaid {} sats; {} sats remaining debt", payment, remaining_sats);
        Ok(actual_payment)
    }

    // ── Interest accrual ────────────────────────────────────────────────────

    /// Accrue interest for all open borrow positions since `last_update`.
    ///
    /// This is called at the start of every mutating operation to ensure the
    /// pool state is always up to date before any new action is taken.
    pub fn accrue_interest(&mut self, current_height: BlockHeight) {
        let blocks_elapsed = current_height.0.saturating_sub(self.last_update.0) as u64;
        if blocks_elapsed == 0 {
            return;
        }

        // Accrue per borrow position.
        let mut new_interest_total: u64 = 0;
        for pos in self.borrowers.values_mut() {
            let blocks = current_height.0.saturating_sub(pos.last_update.0) as u64;
            // interest = principal * annual_rate * blocks / blocks_per_year
            //           (all in satoshis * basis_points / 10_000 / blocks_per_year)
            let interest_sats = pos.principal.sats()
                * pos.borrow_rate_bps
                * blocks
                / (10_000 * BLOCKS_PER_YEAR);
            pos.accrued_interest = Amount(pos.accrued_interest.sats() + interest_sats);
            pos.last_update      = current_height;
            new_interest_total  += interest_sats;
        }

        // Interest flows into total_deposits, increasing the exchange rate.
        self.total_deposits += new_interest_total;
        self.last_update     = current_height;
    }

    // ── Getters ─────────────────────────────────────────────────────────────

    /// Returns a summary of current pool metrics.
    pub fn metrics(&self) -> PoolMetrics {
        PoolMetrics {
            total_deposits:  Amount(self.total_deposits),
            total_borrows:   Amount(self.total_borrows),
            available:       Amount(self.total_deposits.saturating_sub(self.total_borrows)),
            utilisation_bps: self.utilisation_bps(),
            borrow_rate_bps: self.borrow_rate_bps(),
            supply_rate_bps: self.supply_rate_bps(),
            exchange_rate:   self.exchange_rate(),
        }
    }
}

/// A snapshot of pool state metrics for display / monitoring.
#[derive(Debug, Clone)]
pub struct PoolMetrics {
    pub total_deposits:  Amount,
    pub total_borrows:   Amount,
    pub available:       Amount,
    pub utilisation_bps: u64,
    pub borrow_rate_bps: u64,
    pub supply_rate_bps: u64,
    /// Satoshis per share × 1,000,000.
    pub exchange_rate:   u64,
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deposit_and_withdraw_roundtrip() {
        let mut pool = LendingPool::new(BlockHeight(0));
        pool.deposit("alice".into(), Amount(1_000_000), BlockHeight(0)).unwrap();

        let m = pool.metrics();
        assert_eq!(m.total_deposits.sats(), 1_000_000);
        assert_eq!(m.utilisation_bps, 0);

        let shares = pool.lenders["alice"].shares;
        let returned = pool.withdraw("alice", shares, BlockHeight(0)).unwrap();
        assert_eq!(returned.sats(), 1_000_000);
    }

    #[test]
    fn borrow_increases_utilisation() {
        let mut pool = LendingPool::new(BlockHeight(0));
        pool.deposit("lp".into(), Amount(2_000_000), BlockHeight(0)).unwrap();
        pool.borrow(
            "bob".into(),
            Amount(1_000_000),
            Amount(1_600_000), // 160% collateral
            BlockHeight(0),
        ).unwrap();

        assert_eq!(pool.utilisation_bps(), 5_000); // 50%
        assert!(pool.borrow_rate_bps() > RATE_AT_ZERO_UTIL_BPS);
    }

    #[test]
    fn borrow_rate_jumps_above_optimal() {
        let mut pool = LendingPool::new(BlockHeight(0));
        pool.deposit("lp".into(), Amount(10_000_000), BlockHeight(0)).unwrap();
        pool.borrow(
            "heavy".into(),
            Amount(9_500_000), // 95% utilisation
            Amount(15_000_000),
            BlockHeight(0),
        ).unwrap();

        let rate = pool.borrow_rate_bps();
        // Should be well above the optimal rate due to the steep second slope.
        assert!(rate > RATE_AT_OPTIMAL_UTIL_BPS,
            "Rate {} should exceed optimal rate {}", rate, RATE_AT_OPTIMAL_UTIL_BPS);
    }

    #[test]
    fn insufficient_collateral_rejected() {
        let mut pool = LendingPool::new(BlockHeight(0));
        pool.deposit("lp".into(), Amount(2_000_000), BlockHeight(0)).unwrap();
        let result = pool.borrow(
            "undercollateralised".into(),
            Amount(1_000_000),
            Amount(1_000_000), // exactly 100% — below 150% requirement
            BlockHeight(0),
        );
        assert!(matches!(result, Err(BtcFiError::InsufficientCollateral { .. })));
    }

    #[test]
    fn interest_accrues_over_blocks() {
        let mut pool = LendingPool::new(BlockHeight(0));
        pool.deposit("lp".into(), Amount(10_000_000), BlockHeight(0)).unwrap();
        pool.borrow(
            "borrower".into(),
            Amount(5_000_000),
            Amount(8_000_000),
            BlockHeight(0),
        ).unwrap();

        // Accrue one year of interest.
        pool.accrue_interest(BlockHeight(BLOCKS_PER_YEAR as u32));

        let debt = pool.borrowers["borrower"].total_debt().unwrap();
        assert!(debt.sats() > 5_000_000, "Debt should have grown with interest");
    }
}