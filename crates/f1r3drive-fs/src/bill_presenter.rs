//! Per-wallet override of the greedy denomination decomposition.
//!
//! The oracular balance is a single integer. `decompose(balance)`
//! produces one valid breakdown — biggest denomination first — and
//! that's what the `.tokens/` directory shows by default. The macOS
//! Finder extension's "Change" action lets the user ask for a
//! different breakdown of the SAME balance: break one bill of a
//! given denomination into ten of the next-smaller denomination.
//!
//! Per ADR-0001 §Finder extension gRPC server, this is **purely a
//! client-side presentation**. The on-chain balance never changes.
//! We track overrides in-memory, keyed by `RevAddress`. Any
//! transfer-in-or-out invalidates the override — the balance moved,
//! so the user's prior shape no longer matches total — and the next
//! readdir falls back to greedy decomposition against the fresh
//! balance.
//!
//! Scope: COMBINE is not implemented here (returns an error from
//! the ext server). CHANGE on the smallest denomination (`1`) also
//! errors; there is no next-smaller.

use std::collections::HashMap;
use std::sync::RwLock;

use f1r3drive_wallet::{decompose, DenomBill, RevAddress, DENOMINATIONS};
use thiserror::Error;

/// Thread-safe override map plus the greedy fallback. Clone-cheap:
/// everything behind an `RwLock`.
#[derive(Debug, Default)]
pub struct BillPresenter {
    /// Per-address custom bill shape, if the user has broken a bill
    /// via the extension's `CHANGE` action. Order within the vec is
    /// the same as a greedy decomposition's: largest denomination
    /// first; zero-count rows are omitted.
    overrides: RwLock<HashMap<RevAddress, Vec<DenomBill>>>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChangeError {
    #[error("cannot change the smallest denomination (1)")]
    SmallestDenom,
    #[error("denomination {0} is not one of the 19 known denominations")]
    UnknownDenom(u64),
    #[error("wallet has no bills of denomination {0} to break")]
    NoSuchBill(u64),
}

impl BillPresenter {
    pub fn new() -> Self {
        Self::default()
    }

    /// What `.tokens/` readdir should emit for `address`. If an
    /// override is set it wins; otherwise greedy against `balance`.
    pub fn bills_for(&self, address: &RevAddress, balance: u64) -> Vec<DenomBill> {
        if let Some(bills) = self
            .overrides
            .read()
            .expect("BillPresenter lock poisoned")
            .get(address)
            .cloned()
        {
            return bills;
        }
        decompose(balance)
    }

    /// Apply the Finder-extension `CHANGE` action: break one bill of
    /// `denom` into ten bills of `denom / 10`.
    ///
    /// If no override is currently set for `address`, we seed it
    /// from the greedy decomposition of `balance` first; the user's
    /// subsequent `CHANGE` calls then accumulate against that shape.
    pub fn change_denom(
        &self,
        address: &RevAddress,
        balance: u64,
        denom: u64,
    ) -> Result<(), ChangeError> {
        if !DENOMINATIONS.contains(&denom) {
            return Err(ChangeError::UnknownDenom(denom));
        }
        if denom == 1 {
            return Err(ChangeError::SmallestDenom);
        }
        let smaller = denom / 10;

        let mut g = self.overrides.write().expect("BillPresenter lock poisoned");
        let bills = g
            .entry(address.clone())
            .or_insert_with(|| decompose(balance));
        apply_change(bills, denom, smaller)
    }

    /// Drop any override for `address`. Called by `WalletFs`
    /// after a successful transfer touches `address` (as sender or
    /// receiver) — the balance has moved, so the user's prior
    /// custom shape no longer refers to a valid total.
    pub fn invalidate(&self, address: &RevAddress) {
        self.overrides
            .write()
            .expect("BillPresenter lock poisoned")
            .remove(address);
    }

    /// `true` iff `address` currently has an override active.
    pub fn has_override(&self, address: &RevAddress) -> bool {
        self.overrides
            .read()
            .expect("BillPresenter lock poisoned")
            .contains_key(address)
    }
}

/// Decrement one bill of `denom` and insert ten of `smaller`, in
/// place. Preserves the "largest first, no zero-count rows"
/// invariant.
fn apply_change(bills: &mut Vec<DenomBill>, denom: u64, smaller: u64) -> Result<(), ChangeError> {
    // Find the row carrying `denom`, remove one bill from it.
    let denom_idx = bills
        .iter()
        .position(|b| b.denom == denom && b.count > 0)
        .ok_or(ChangeError::NoSuchBill(denom))?;
    bills[denom_idx].count -= 1;
    if bills[denom_idx].count == 0 {
        bills.remove(denom_idx);
    }

    // Add 10 to the `smaller`-denom row (or create one if absent).
    match bills.iter().position(|b| b.denom == smaller) {
        Some(i) => bills[i].count += 10,
        None => {
            // Keep the vec sorted largest-first. Find the insertion
            // index.
            let insert_at = bills
                .iter()
                .position(|b| b.denom < smaller)
                .unwrap_or(bills.len());
            bills.insert(
                insert_at,
                DenomBill {
                    denom: smaller,
                    count: 10,
                },
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn validator_addr() -> RevAddress {
        let pk = hex::decode(
            "04ffc016579a68050d655d55df4e09f04605164543e257c8e6df10361e6068a5336588e9b355ea859c5ab4285a5ef0efdf62bc28b80320ce99e26bb1607b3ad93d",
        )
        .unwrap();
        RevAddress::from_public_key_bytes(&pk).unwrap()
    }

    #[test]
    fn no_override_falls_back_to_greedy() {
        let p = BillPresenter::new();
        let addr = validator_addr();
        let bills = p.bills_for(&addr, 1234);
        assert_eq!(bills, decompose(1234));
    }

    #[test]
    fn change_breaks_bill_into_ten_smaller() {
        let p = BillPresenter::new();
        let addr = validator_addr();
        // Balance 1000 = 1×1000. CHANGE 1000 → 10×100.
        p.change_denom(&addr, 1000, 1000).unwrap();
        let bills = p.bills_for(&addr, 1000);
        assert_eq!(
            bills,
            vec![DenomBill {
                denom: 100,
                count: 10
            }],
        );
        // Total value preserved.
        assert_eq!(f1r3drive_wallet::total(&bills), 1000);
    }

    #[test]
    fn change_accumulates_with_existing_smaller_row() {
        let p = BillPresenter::new();
        let addr = validator_addr();
        // Balance 1200 = 1×1000 + 2×100. CHANGE 1000 → 2 + 10 = 12×100.
        p.change_denom(&addr, 1200, 1000).unwrap();
        let bills = p.bills_for(&addr, 1200);
        assert_eq!(
            bills,
            vec![DenomBill {
                denom: 100,
                count: 12
            }],
        );
    }

    #[test]
    fn change_on_smallest_denom_errors() {
        let p = BillPresenter::new();
        let addr = validator_addr();
        assert_eq!(
            p.change_denom(&addr, 10, 1),
            Err(ChangeError::SmallestDenom),
        );
    }

    #[test]
    fn change_on_unknown_denom_errors() {
        let p = BillPresenter::new();
        let addr = validator_addr();
        assert_eq!(
            p.change_denom(&addr, 100, 42),
            Err(ChangeError::UnknownDenom(42)),
        );
    }

    #[test]
    fn change_on_bill_not_present_errors() {
        let p = BillPresenter::new();
        let addr = validator_addr();
        // Balance 50 has no 1000-denom bill.
        assert_eq!(
            p.change_denom(&addr, 50, 1000),
            Err(ChangeError::NoSuchBill(1000)),
        );
    }

    #[test]
    fn invalidate_drops_override() {
        let p = BillPresenter::new();
        let addr = validator_addr();
        p.change_denom(&addr, 1000, 1000).unwrap();
        assert!(p.has_override(&addr));
        p.invalidate(&addr);
        assert!(!p.has_override(&addr));
        // Falls back to greedy on fresh balance.
        assert_eq!(p.bills_for(&addr, 2000), decompose(2000));
    }

    #[test]
    fn change_preserves_largest_first_order() {
        let p = BillPresenter::new();
        let addr = validator_addr();
        // 11_000 = 1×10_000 + 1×1000. CHANGE 1000 → 1×10_000 + 10×100.
        p.change_denom(&addr, 11_000, 1000).unwrap();
        let bills = p.bills_for(&addr, 11_000);
        assert_eq!(
            bills,
            vec![
                DenomBill {
                    denom: 10_000,
                    count: 1
                },
                DenomBill {
                    denom: 100,
                    count: 10
                },
            ],
        );
    }
}
