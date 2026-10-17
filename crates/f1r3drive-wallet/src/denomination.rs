//! Denomination constants + greedy decomposition.
//!
//! Mirrors the Java f1r3drive's `TokenDirectory.denominations` list
//! verbatim: 19 fixed values, powers of 10 from 10⁰ (`1`) up to 10¹⁸
//! (`1_000_000_000_000_000_000`). Greedy top-down decomposition —
//! break a `balance` into bills of the largest denomination that fits,
//! then recurse on the remainder — is purely cosmetic (ADR-0001:
//! *Denomination decomposition is a client-side presentation choice,
//! not an on-chain constraint*), but the Finder extension's "CHANGE"
//! action expects the same decomposition the daemon emits, so we
//! must match the Java shape exactly.
//!
//! Representable range: `u64::MAX` fits in 10¹⁹, which would overflow
//! our 10¹⁸ cap by a factor of ~18. In practice REV balances are
//! `i64` on the chain and no genesis wallet gets anywhere close to
//! 10¹⁸ anyway; still, we return the decomposition as-is and let the
//! caller detect over-the-cap residue if they care.

/// The 19 fixed denominations, largest to smallest.
pub const DENOMINATIONS: [u64; 19] = [
    1_000_000_000_000_000_000, // 10^18
    100_000_000_000_000_000,
    10_000_000_000_000_000,
    1_000_000_000_000_000,
    100_000_000_000_000,
    10_000_000_000_000,
    1_000_000_000_000,
    100_000_000_000,
    10_000_000_000,
    1_000_000_000,
    100_000_000,
    10_000_000,
    1_000_000,
    100_000,
    10_000,
    1_000,
    100,
    10,
    1, // 10^0
];

/// One row of a decomposition: `count` bills of face value `denom`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DenomBill {
    pub denom: u64,
    pub count: u64,
}

/// Greedy top-down decomposition of `balance` into
/// [`DENOMINATIONS`] bills. Any residue under 1 (impossible, since
/// 1 is a denomination) would silently disappear; the smallest denom
/// `1` guarantees `sum(count * denom) == balance`.
///
/// Zero-count rows are omitted — callers rendering a `.tokens/`
/// directory listing want "no entries for denom D" to look like "no
/// entries", not like one empty entry.
pub fn decompose(balance: u64) -> Vec<DenomBill> {
    let mut out = Vec::with_capacity(DENOMINATIONS.len());
    let mut remaining = balance;
    for &denom in &DENOMINATIONS {
        let count = remaining / denom;
        if count > 0 {
            out.push(DenomBill { denom, count });
            remaining -= count * denom;
        }
    }
    debug_assert_eq!(
        remaining, 0,
        "decomposition should be exact (smallest denom is 1)"
    );
    out
}

/// Short-circuit: total value of a decomposition. Useful for
/// round-trip assertions and for the Finder-ext `CHANGE` action
/// (verify ten-of-next-smaller equals one of this).
pub fn total(bills: &[DenomBill]) -> u64 {
    bills.iter().map(|b| b.denom.saturating_mul(b.count)).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denominations_are_strictly_descending_powers_of_ten() {
        assert_eq!(DENOMINATIONS.len(), 19);
        assert_eq!(DENOMINATIONS[0], 1_000_000_000_000_000_000);
        assert_eq!(DENOMINATIONS[18], 1);
        for pair in DENOMINATIONS.windows(2) {
            assert_eq!(pair[0], pair[1] * 10, "not a strict ×10 descent");
        }
    }

    #[test]
    fn decompose_zero_is_empty() {
        assert_eq!(decompose(0), vec![]);
    }

    #[test]
    fn decompose_matches_hand_worked_examples() {
        // 1234 → 1×1000 + 2×100 + 3×10 + 4×1 (matches the
        // Java TokenDirectory doc comment).
        assert_eq!(
            decompose(1234),
            vec![
                DenomBill {
                    denom: 1_000,
                    count: 1
                },
                DenomBill {
                    denom: 100,
                    count: 2
                },
                DenomBill {
                    denom: 10,
                    count: 3
                },
                DenomBill { denom: 1, count: 4 },
            ],
        );
    }

    #[test]
    fn decompose_single_bill_cases() {
        for &denom in &DENOMINATIONS {
            assert_eq!(decompose(denom), vec![DenomBill { denom, count: 1 }]);
        }
    }

    #[test]
    fn decompose_total_round_trips() {
        let samples = [
            0u64,
            1,
            9,
            10,
            99,
            100,
            999_999,
            1_000_000,
            50_000_000_000_000_000,
            123_456_789_012_345_678,
            u64::MAX / 2,
        ];
        for &b in &samples {
            let bills = decompose(b);
            assert_eq!(total(&bills), b, "roundtrip for {b}");
        }
    }

    #[test]
    fn decompose_skips_zero_count_rows() {
        // 100 should only emit a single row (1×100), not slots for
        // 10 or 1 with count=0.
        let bills = decompose(100);
        assert_eq!(bills.len(), 1);
    }
}
