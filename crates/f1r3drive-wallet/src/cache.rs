//! TTL-bounded balance cache.
//!
//! A thin wrapper over an in-process `HashMap<RevAddress, Entry>` that
//! lazily refreshes an entry when it's missing or older than `ttl`.
//! The actual on-chain fetch is injected: callers hand in an async
//! closure that takes a `RevAddress` and returns an `i64` balance.
//! This keeps `f1r3drive-wallet` free of gRPC / Rholang deps — the
//! glue layer in `f1r3drive` wires the real fetch via
//! `f1r3drive-rho::check_balance_snippet` + `NodeClient`.
//!
//! Per ADR-0001:
//! - TTL default is 5s. The daemon re-fetches on access when stale.
//! - On fetch error, we serve stale (if any) and surface the error
//!   through `tracing::warn!` at the call site — we do NOT burn the
//!   last-known-good value.
//! - On a known-good write (`invalidate`), the next access refetches
//!   immediately regardless of TTL.
//!
//! Concurrency: multiple callers racing to refresh the same stale
//! entry currently fire multiple fetches. Single-flight dedup would
//! be a Stage 3/4 refinement; for now the exploratory_deploy cost is
//! cheap enough on a local shard and the balance values are
//! idempotent — the last writer wins.

use std::collections::HashMap;
use std::future::Future;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use crate::address::RevAddress;

/// Default TTL, matching ADR-0001 §Balance cache.
pub const DEFAULT_TTL: Duration = Duration::from_secs(5);

/// One cached balance observation.
#[derive(Clone, Copy, Debug)]
pub struct Entry {
    pub balance: i64,
    pub fetched_at: Instant,
}

/// TTL-bounded in-memory balance cache.
#[derive(Debug)]
pub struct BalanceCache {
    ttl: Duration,
    inner: RwLock<HashMap<RevAddress, Entry>>,
}

impl Default for BalanceCache {
    fn default() -> Self {
        Self::with_ttl(DEFAULT_TTL)
    }
}

impl BalanceCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: RwLock::new(HashMap::new()),
        }
    }

    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Fresh entry for `address` if one is cached and still within
    /// TTL; `None` if missing or stale. Does NOT fetch.
    pub fn peek(&self, address: &RevAddress) -> Option<Entry> {
        let g = self.inner.read().expect("BalanceCache lock poisoned");
        let e = g.get(address)?;
        if e.fetched_at.elapsed() <= self.ttl {
            Some(*e)
        } else {
            None
        }
    }

    /// Clear the entry for `address` (used on successful transfer).
    pub fn invalidate(&self, address: &RevAddress) {
        self.inner
            .write()
            .expect("BalanceCache lock poisoned")
            .remove(address);
    }

    /// Replace the cached entry for `address` with a just-fetched
    /// value. Timestamped at `Instant::now()`.
    pub fn put(&self, address: RevAddress, balance: i64) {
        let now = Instant::now();
        self.inner
            .write()
            .expect("BalanceCache lock poisoned")
            .insert(
                address,
                Entry {
                    balance,
                    fetched_at: now,
                },
            );
    }

    /// Fetch-or-return-cached. If a fresh entry exists, returns it.
    /// Otherwise calls `fetch(address)`, stores the result, and
    /// returns it. On fetch error, returns the stale entry if any
    /// (via `Err(FetchError::Stale { last_known, err })`) or the raw
    /// error (if no stale entry).
    pub async fn get_or_fetch<F, Fut, E>(
        &self,
        address: &RevAddress,
        fetch: F,
    ) -> Result<i64, FetchError<E>>
    where
        F: FnOnce(&RevAddress) -> Fut,
        Fut: Future<Output = Result<i64, E>>,
    {
        if let Some(e) = self.peek(address) {
            return Ok(e.balance);
        }

        match fetch(address).await {
            Ok(balance) => {
                self.put(address.clone(), balance);
                Ok(balance)
            }
            Err(err) => {
                // Serve stale if we have it (ignoring TTL this time)
                // so transient fetch failures don't blank the user's
                // view of their wallet.
                let stale = self
                    .inner
                    .read()
                    .expect("BalanceCache lock poisoned")
                    .get(address)
                    .copied();
                match stale {
                    Some(e) => Err(FetchError::Stale { last_known: e, err }),
                    None => Err(FetchError::NoCache(err)),
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.inner.read().expect("BalanceCache lock poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What a `get_or_fetch` returns when the underlying fetch fails.
///
/// `Stale { last_known, err }` means we served stale from the cache
/// *into the error channel* — the caller gets a last-known-good
/// balance to show the user AND the underlying error for logging.
/// `NoCache(err)` means we had nothing cached, so the error is all
/// there is.
#[derive(Debug)]
pub enum FetchError<E> {
    Stale { last_known: Entry, err: E },
    NoCache(E),
}

impl<E> FetchError<E> {
    /// If we have *any* balance to show (fresh or stale), return it.
    pub fn last_known_balance(&self) -> Option<i64> {
        match self {
            Self::Stale { last_known, .. } => Some(last_known.balance),
            Self::NoCache(_) => None,
        }
    }

    /// Unwrap the inner fetch error for logging.
    pub fn into_err(self) -> E {
        match self {
            Self::Stale { err, .. } => err,
            Self::NoCache(err) => err,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn fake_address(seed: u8) -> RevAddress {
        let eth = format!("{:040x}", seed as u128);
        RevAddress::from_eth_address(&eth).unwrap()
    }

    #[tokio::test]
    async fn fetch_populates_cache_on_miss() {
        let cache = BalanceCache::new();
        let addr = fake_address(1);
        let bal = cache
            .get_or_fetch(&addr, |_| async { Ok::<_, ()>(100) })
            .await
            .unwrap();
        assert_eq!(bal, 100);
        assert_eq!(cache.peek(&addr).unwrap().balance, 100);
    }

    #[tokio::test]
    async fn second_call_within_ttl_hits_cache() {
        let cache = BalanceCache::new();
        let addr = fake_address(1);
        let calls = Arc::new(AtomicUsize::new(0));

        let c = calls.clone();
        cache
            .get_or_fetch(&addr, |_| {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::Relaxed);
                    Ok::<_, ()>(42)
                }
            })
            .await
            .unwrap();

        let c = calls.clone();
        let v = cache
            .get_or_fetch(&addr, |_| {
                let c = c.clone();
                async move {
                    c.fetch_add(1, Ordering::Relaxed);
                    Ok::<_, ()>(99)
                }
            })
            .await
            .unwrap();

        assert_eq!(v, 42, "second call should serve cached, not refetched");
        assert_eq!(calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn invalidate_forces_refetch() {
        let cache = BalanceCache::new();
        let addr = fake_address(1);

        cache
            .get_or_fetch(&addr, |_| async { Ok::<_, ()>(10) })
            .await
            .unwrap();
        cache.invalidate(&addr);
        let v = cache
            .get_or_fetch(&addr, |_| async { Ok::<_, ()>(20) })
            .await
            .unwrap();
        assert_eq!(v, 20);
    }

    #[tokio::test]
    async fn stale_entry_outside_ttl_is_refetched() {
        let cache = BalanceCache::with_ttl(Duration::from_millis(50));
        let addr = fake_address(1);

        cache
            .get_or_fetch(&addr, |_| async { Ok::<_, ()>(1) })
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(80)).await;

        let v = cache
            .get_or_fetch(&addr, |_| async { Ok::<_, ()>(2) })
            .await
            .unwrap();
        assert_eq!(v, 2);
    }

    #[tokio::test]
    async fn fetch_error_without_cache_returns_no_cache() {
        let cache = BalanceCache::new();
        let addr = fake_address(1);
        let err = cache
            .get_or_fetch(&addr, |_| async { Err::<i64, _>("boom") })
            .await
            .unwrap_err();
        assert!(matches!(err, FetchError::NoCache(_)));
    }

    #[tokio::test]
    async fn fetch_error_with_cache_returns_stale() {
        let cache = BalanceCache::with_ttl(Duration::from_millis(50));
        let addr = fake_address(1);
        cache
            .get_or_fetch(&addr, |_| async { Ok::<_, &str>(123) })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;

        let err = cache
            .get_or_fetch(&addr, |_| async { Err::<i64, _>("transient") })
            .await
            .unwrap_err();
        assert_eq!(err.last_known_balance(), Some(123));
    }

    #[test]
    fn put_and_peek_round_trip() {
        let cache = BalanceCache::new();
        let addr = fake_address(1);
        cache.put(addr.clone(), 777);
        assert_eq!(cache.peek(&addr).unwrap().balance, 777);
    }

    #[test]
    fn peek_on_stale_returns_none() {
        let cache = BalanceCache::with_ttl(Duration::from_millis(10));
        let addr = fake_address(1);
        cache.put(addr.clone(), 1);
        std::thread::sleep(Duration::from_millis(30));
        assert!(cache.peek(&addr).is_none());
    }
}
