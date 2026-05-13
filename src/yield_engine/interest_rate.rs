// =============================================================================
// src/yield_engine/interest_rate.rs — Interest Rate Model
// =============================================================================
//
// Utilisation-based interest rate model for BTC lending.
// Implements Aave v2's two-slope model.

// ── Rate constants ────────────────────────────────────────────────────────────

/// Interest rate at 0% utilisation (annual basis points).
/// 50 bp = 0.50% APR.
pub const RATE_AT_ZERO_UTIL_BPS: u64 = 50;

/// Interest rate at optimal utilisation (annual basis points).
/// 500 bp = 5.00% APR.
pub const RATE_AT_OPTIMAL_UTIL_BPS: u64 = 500;

/// Interest rate at 100% utilisation (annual basis points).
/// 10_000 bp = 100% APR — very high to deter full utilisation.
pub const RATE_AT_MAX_UTIL_BPS: u64 = 10_000;

/// Target utilisation ratio in basis points.
/// 8_000 = 80% — above this the rate climbs steeply.
pub const OPTIMAL_UTILISATION_BPS: u64 = 8_000;

/// Bitcoin blocks per year (10-minute average block time).
pub const BLOCKS_PER_YEAR: u64 = 52_560;

// ── Interest Rate Model ───────────────────────────────────────────────────────

/// Calculate utilisation ratio in basis points.
pub fn utilisation_bps(total_borrows: u64, total_deposits: u64) -> u64 {
    if total_deposits == 0 {
        return 0;
    }
    ((total_borrows * 10_000) / total_deposits).min(10_000)
}

/// Calculate borrow rate in annual basis points using two-slope model.
pub fn borrow_rate_bps(utilisation: u64) -> u64 {
    if utilisation <= OPTIMAL_UTILISATION_BPS {
        // Slope 1: linear from r0 to r*
        RATE_AT_ZERO_UTIL_BPS
            + utilisation * (RATE_AT_OPTIMAL_UTIL_BPS - RATE_AT_ZERO_UTIL_BPS)
                / OPTIMAL_UTILISATION_BPS
    } else {
        // Slope 2: linear from r* to rM above optimal utilisation
        RATE_AT_OPTIMAL_UTIL_BPS
            + (utilisation - OPTIMAL_UTILISATION_BPS)
                * (RATE_AT_MAX_UTIL_BPS - RATE_AT_OPTIMAL_UTIL_BPS)
                / (10_000 - OPTIMAL_UTILISATION_BPS)
    }
}

/// Calculate supply (deposit) rate in annual basis points.
pub fn supply_rate_bps(borrow_rate: u64, utilisation: u64) -> u64 {
    borrow_rate * utilisation / 10_000
}

/// Convert annual basis-point rate to per-block accrual factor.
pub fn per_block_rate(annual_bps: u64) -> u64 {
    annual_bps
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_utilisation_rate() {
        let rate = borrow_rate_bps(0);
        assert_eq!(rate, RATE_AT_ZERO_UTIL_BPS);
    }

    #[test]
    fn optimal_utilisation_rate() {
        let rate = borrow_rate_bps(OPTIMAL_UTILISATION_BPS);
        assert_eq!(rate, RATE_AT_OPTIMAL_UTIL_BPS);
    }

    #[test]
    fn max_utilisation_rate() {
        let rate = borrow_rate_bps(10_000);
        assert_eq!(rate, RATE_AT_MAX_UTIL_BPS);
    }

    #[test]
    fn rate_increases_with_utilisation() {
        let low = borrow_rate_bps(4_000);
        let high = borrow_rate_bps(8_000);
        assert!(high > low);
    }

    #[test]
    fn supply_rate_proportional_to_utilisation() {
        let borrow_rate = 1_000;
        let util = 5_000;
        let supply_rate = supply_rate_bps(borrow_rate, util);
        assert_eq!(supply_rate, 500); // borrow_rate * util / 10_000
    }
}
