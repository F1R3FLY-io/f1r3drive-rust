//! Wallet state + in-memory registry.
//!
//! Pure data + synchronised accessors. No I/O; the daemon layer
//! above wires on-chain reads into [`WalletRegistry::upsert_balance`]
//! and gates unlock operations through [`WalletRegistry::unlock`].
//!
//! Per ADR-0001 (`docs/architecture/ADR-0001-token-as-file.md`):
//! - The registry is in-process, dropped on daemon restart.
//! - Unlocked wallets are keyed by `RevAddress`; the signing key
//!   stays with the caller (`f1r3drive-ext`'s `UnlockWalletDirectory`
//!   RPC) and never lands in a registry field — persisting private
//!   keys would leak them into the oracular bundle if the user
//!   tracks the daemon's own state dir.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::address::RevAddress;

/// Lock state of a wallet from the daemon's point of view.
///
/// `Locked` is the baseline — we know the address exists but we
/// have no signing key, so transfers *out* of it error. `Unlocked`
/// means `f1r3drive-ext::UnlockWalletDirectory` validated a signing
/// key that derives to this address; the daemon can now sign
/// transfers from it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LockState {
    Locked,
    Unlocked,
}

/// Snapshot of what the daemon knows about one wallet.
///
/// `balance` is `i64` to match the on-chain `rho:vault:system` balance
/// type (which can also store a sentinel `-1` while a vault is being
/// created). Observed-at timestamps belong on the cache layer, not
/// here — this type is just the fact.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WalletState {
    pub address: RevAddress,
    pub balance: i64,
    pub lock_state: LockState,
}

impl WalletState {
    pub fn locked(address: RevAddress) -> Self {
        Self {
            address,
            balance: 0,
            lock_state: LockState::Locked,
        }
    }

    pub fn is_unlocked(&self) -> bool {
        self.lock_state == LockState::Unlocked
    }
}

/// Thread-safe in-memory registry of known wallets.
///
/// Lookups are cheap (`RwLock<HashMap>`); updates take the write
/// lock. The daemon's FUSE path hits this registry for every
/// `readdir /` call, so lock contention has to stay bounded —
/// current callers hit each wallet at most once per `readdir` cycle.
#[derive(Default, Debug)]
pub struct WalletRegistry {
    inner: RwLock<HashMap<RevAddress, WalletState>>,
}

impl WalletRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Track a wallet as `Locked`. No-op if the registry already has
    /// an entry for `address` (we never downgrade `Unlocked` →
    /// `Locked` as a side effect of `track`; use [`Self::lock`] for
    /// that, which isn't currently needed by any caller).
    pub fn track(&self, address: RevAddress) {
        let mut g = self.inner.write().expect("WalletRegistry lock poisoned");
        g.entry(address.clone())
            .or_insert_with(|| WalletState::locked(address));
    }

    /// Mark a tracked wallet as `Unlocked`. Also inserts it as
    /// `Unlocked` if not already present — the daemon's unlock path
    /// is "I just verified a private key for this address, treat it
    /// as unlocked", which must work whether or not we were already
    /// tracking the address as locked.
    pub fn unlock(&self, address: RevAddress) {
        let mut g = self.inner.write().expect("WalletRegistry lock poisoned");
        let entry = g.entry(address.clone()).or_insert_with(|| WalletState {
            address: address.clone(),
            balance: 0,
            lock_state: LockState::Unlocked,
        });
        entry.lock_state = LockState::Unlocked;
    }

    /// Replace the cached balance for `address`. Creates the entry
    /// as `Locked` if unknown — balance is observable from any
    /// vault; discovery via balance should not pretend to unlock.
    pub fn upsert_balance(&self, address: &RevAddress, balance: i64) {
        let mut g = self.inner.write().expect("WalletRegistry lock poisoned");
        let entry = g
            .entry(address.clone())
            .or_insert_with(|| WalletState::locked(address.clone()));
        entry.balance = balance;
    }

    /// Point-in-time snapshot of one wallet, or `None` if untracked.
    pub fn get(&self, address: &RevAddress) -> Option<WalletState> {
        self.inner
            .read()
            .expect("WalletRegistry lock poisoned")
            .get(address)
            .cloned()
    }

    /// Point-in-time snapshot of every tracked wallet. Ordering is
    /// unspecified — the FUSE-side `readdir` sorts for display.
    pub fn snapshot(&self) -> Vec<WalletState> {
        self.inner
            .read()
            .expect("WalletRegistry lock poisoned")
            .values()
            .cloned()
            .collect()
    }

    pub fn len(&self) -> usize {
        self.inner
            .read()
            .expect("WalletRegistry lock poisoned")
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALIDATOR_PUBKEY_HEX: &str = "04ffc016579a68050d655d55df4e09f04605164543e257c8e6df10361e6068a5336588e9b355ea859c5ab4285a5ef0efdf62bc28b80320ce99e26bb1607b3ad93d";

    fn fake_address(seed: u8) -> RevAddress {
        // A valid-shaped but synthetic ETH address — we're testing
        // registry mechanics, not derivation.
        let eth = format!("{:040x}", seed as u128);
        RevAddress::from_eth_address(&eth).unwrap()
    }

    #[test]
    fn track_inserts_locked() {
        let reg = WalletRegistry::new();
        let a = fake_address(1);
        reg.track(a.clone());
        let got = reg.get(&a).unwrap();
        assert_eq!(got.lock_state, LockState::Locked);
        assert_eq!(got.balance, 0);
    }

    #[test]
    fn track_is_idempotent_and_does_not_relock() {
        let reg = WalletRegistry::new();
        let a = fake_address(1);
        reg.unlock(a.clone());
        reg.track(a.clone()); // no-op on already-present entry
        let got = reg.get(&a).unwrap();
        assert_eq!(got.lock_state, LockState::Unlocked);
    }

    #[test]
    fn unlock_promotes_existing_locked() {
        let reg = WalletRegistry::new();
        let a = fake_address(1);
        reg.track(a.clone());
        reg.unlock(a.clone());
        assert_eq!(reg.get(&a).unwrap().lock_state, LockState::Unlocked);
    }

    #[test]
    fn unlock_creates_if_missing() {
        let reg = WalletRegistry::new();
        let a = fake_address(2);
        reg.unlock(a.clone());
        assert_eq!(reg.get(&a).unwrap().lock_state, LockState::Unlocked);
    }

    #[test]
    fn upsert_balance_preserves_lock_state() {
        let reg = WalletRegistry::new();
        let a = fake_address(1);
        reg.unlock(a.clone());
        reg.upsert_balance(&a, 42);
        let got = reg.get(&a).unwrap();
        assert_eq!(got.balance, 42);
        assert_eq!(got.lock_state, LockState::Unlocked);
    }

    #[test]
    fn upsert_balance_tracks_unknown_as_locked() {
        let reg = WalletRegistry::new();
        let a = fake_address(3);
        reg.upsert_balance(&a, 1_000);
        let got = reg.get(&a).unwrap();
        assert_eq!(got.lock_state, LockState::Locked);
        assert_eq!(got.balance, 1_000);
    }

    #[test]
    fn snapshot_sees_every_tracked_wallet() {
        let reg = WalletRegistry::new();
        for i in 1u8..=5 {
            reg.track(fake_address(i));
        }
        assert_eq!(reg.len(), 5);
        assert_eq!(reg.snapshot().len(), 5);
    }

    #[test]
    fn get_on_unknown_is_none() {
        let reg = WalletRegistry::new();
        assert!(reg.get(&fake_address(99)).is_none());
    }

    #[test]
    fn is_unlocked_matches_state() {
        let a = fake_address(1);
        let locked = WalletState::locked(a.clone());
        assert!(!locked.is_unlocked());
        let unlocked = WalletState {
            address: a,
            balance: 0,
            lock_state: LockState::Unlocked,
        };
        assert!(unlocked.is_unlocked());
    }

    #[test]
    fn registry_works_with_real_derived_address() {
        // Sanity check that the registry's HashMap<RevAddress, _>
        // handles a derivation-produced address identically to one
        // parsed from base58.
        let pk = hex::decode(VALIDATOR_PUBKEY_HEX).unwrap();
        let a = RevAddress::from_public_key_bytes(&pk).unwrap();
        let reg = WalletRegistry::new();
        reg.upsert_balance(&a, 50_000_000_000_000_000);
        let via_parse = RevAddress::parse(&a.to_base58()).unwrap();
        assert_eq!(reg.get(&via_parse).unwrap().balance, 50_000_000_000_000_000);
    }
}
