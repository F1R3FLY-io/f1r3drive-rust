//! Minted-listing registry.
//!
//! Slice 7 introduced the in-process `ListingStore`. Slice 9 adds
//! persistence: when a `state_dir` is attached the store serializes
//! to `<state_dir>/listings.json` on every mutation and loads from
//! it on construction. Daemon restarts preserve the owner's active
//! listings. Cross-daemon discoverability (an on-chain listing
//! manifest Bob can read) stays a later slice.
//!
//! Writes are atomic via tmp-sibling rename, matching the identity
//! bootstrap pattern — a crash mid-write never leaves a half-written
//! JSON file. The in-process `HashMap` stays the source of truth
//! during the daemon's lifetime; the file is a mirror for restart.

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::contract_template::ListingSpec;

/// Filename inside `state_dir` where the mirror lives. Flat JSON
/// over a single file keeps the on-disk shape simple; if listing
/// churn grows we'd switch to one-file-per-id later.
pub const LISTINGS_FILE: &str = "listings.json";

/// A single active listing. Owner is the uncompressed pubkey hex of
/// the user who dropped the file into their own `/<me>/<template>/`
/// subfolder — the one who'll receive REV on purchase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listing {
    pub owner_pubkey_hex: String,
    /// Name of the registered `ContractTemplate` that minted this
    /// listing. Stored as owned `String` so the on-disk form is
    /// portable across daemon restarts (templates don't need to live
    /// at the same `&'static str` address across runs).
    pub template_name: String,
    pub spec: ListingSpec,
}

#[derive(Debug, Error)]
pub enum ListingStoreError {
    #[error("read {0:?}: {1}")]
    ReadFile(PathBuf, #[source] io::Error),
    #[error("write {0:?}: {1}")]
    WriteFile(PathBuf, #[source] io::Error),
    #[error("decode {0:?}: {1}")]
    Decode(PathBuf, #[source] serde_json::Error),
    #[error("encode: {0}")]
    Encode(#[source] serde_json::Error),
}

/// Thread-safe listing table with optional disk persistence.
#[derive(Debug, Default)]
pub struct ListingStore {
    inner: RwLock<HashMap<String, Listing>>,
    /// `Some` → path we serialize to on every mutation; `None` →
    /// pure in-memory (slice-7 behavior, still exercised by many
    /// unit tests that don't need to touch disk).
    file: Option<PathBuf>,
}

impl ListingStore {
    /// Pure-in-memory store. Mutations don't touch disk. Used in
    /// tests + anywhere the daemon doesn't own a `state_dir`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open (or create) a disk-backed store at
    /// `<state_dir>/listings.json`. On construction the file is read
    /// if present and its contents become the initial state.
    pub fn open(state_dir: impl AsRef<Path>) -> Result<Self, ListingStoreError> {
        let file = state_dir.as_ref().join(LISTINGS_FILE);
        let initial = if file.exists() {
            let bytes =
                std::fs::read(&file).map_err(|e| ListingStoreError::ReadFile(file.clone(), e))?;
            if bytes.is_empty() {
                HashMap::new()
            } else {
                serde_json::from_slice::<HashMap<String, Listing>>(&bytes)
                    .map_err(|e| ListingStoreError::Decode(file.clone(), e))?
            }
        } else {
            HashMap::new()
        };
        Ok(Self {
            inner: RwLock::new(initial),
            file: Some(file),
        })
    }

    pub fn insert(&self, id: String, listing: Listing) {
        self.inner.write().unwrap().insert(id, listing);
        self.persist_or_log();
    }

    pub fn get(&self, id: &str) -> Option<Listing> {
        self.inner.read().unwrap().get(id).cloned()
    }

    pub fn remove(&self, id: &str) -> Option<Listing> {
        let out = self.inner.write().unwrap().remove(id);
        if out.is_some() {
            self.persist_or_log();
        }
        out
    }

    /// IDs of every active listing, in no particular order. The
    /// readdir caller sorts for display.
    pub fn ids(&self) -> Vec<String> {
        self.inner.read().unwrap().keys().cloned().collect()
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Serialize the current state to disk atomically. Called under
    /// the read lock after each mutator has already released its
    /// write lock. We log + swallow IO errors rather than failing
    /// the FUSE op — the in-memory state remains correct; the mirror
    /// is best-effort. A follow-up slice can propagate the error if
    /// the UX demands it.
    fn persist_or_log(&self) {
        let Some(path) = self.file.as_ref() else {
            return;
        };
        if let Err(e) = self.persist_to(path) {
            tracing::warn!(err = ?e, path = %path.display(), "listing-store persist failed");
        }
    }

    fn persist_to(&self, path: &Path) -> Result<(), ListingStoreError> {
        let snapshot = self.inner.read().unwrap().clone();
        let bytes = serde_json::to_vec_pretty(&snapshot).map_err(ListingStoreError::Encode)?;
        // Atomic write via tmp-sibling rename.
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, &bytes).map_err(|e| ListingStoreError::WriteFile(tmp.clone(), e))?;
        std::fs::rename(&tmp, path)
            .map_err(|e| ListingStoreError::WriteFile(path.to_path_buf(), e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_listing() -> Listing {
        Listing {
            owner_pubkey_hex: "04".to_string() + &"ab".repeat(64),
            template_name: "Paid transfer".into(),
            spec: ListingSpec::PaidTransfer {
                price: 42,
                filename: "sold.pdf".into(),
            },
        }
    }

    #[test]
    fn insert_and_get_round_trip() {
        let s = ListingStore::new();
        s.insert("deadbeef".into(), sample_listing());
        assert_eq!(s.get("deadbeef"), Some(sample_listing()));
    }

    #[test]
    fn remove_is_idempotent_and_drops_entry() {
        let s = ListingStore::new();
        s.insert("x".into(), sample_listing());
        assert_eq!(s.remove("x"), Some(sample_listing()));
        assert_eq!(s.remove("x"), None);
        assert_eq!(s.get("x"), None);
    }

    #[test]
    fn ids_lists_everything_inserted() {
        let s = ListingStore::new();
        s.insert("a".into(), sample_listing());
        s.insert("b".into(), sample_listing());
        let mut ids = s.ids();
        ids.sort();
        assert_eq!(ids, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn empty_store_is_empty() {
        let s = ListingStore::new();
        assert!(s.is_empty());
        s.insert("x".into(), sample_listing());
        assert!(!s.is_empty());
    }

    #[test]
    fn open_on_fresh_dir_is_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let s = ListingStore::open(tmp.path()).unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn insert_persists_across_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let s1 = ListingStore::open(tmp.path()).unwrap();
        s1.insert("abc".into(), sample_listing());
        drop(s1);

        let s2 = ListingStore::open(tmp.path()).unwrap();
        assert_eq!(s2.get("abc"), Some(sample_listing()));
    }

    #[test]
    fn remove_persists_across_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let s1 = ListingStore::open(tmp.path()).unwrap();
        s1.insert("a".into(), sample_listing());
        s1.insert("b".into(), sample_listing());
        s1.remove("a");
        drop(s1);

        let s2 = ListingStore::open(tmp.path()).unwrap();
        assert_eq!(s2.get("a"), None);
        assert_eq!(s2.get("b"), Some(sample_listing()));
    }

    #[test]
    fn malformed_json_file_is_an_error_on_open() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(LISTINGS_FILE), b"this is not JSON").unwrap();
        assert!(matches!(
            ListingStore::open(tmp.path()),
            Err(ListingStoreError::Decode(_, _)),
        ));
    }

    #[test]
    fn empty_json_file_treated_as_empty_store() {
        // Guards against a half-written legacy file. If someone
        // manually truncates it, we don't panic.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join(LISTINGS_FILE), b"").unwrap();
        let s = ListingStore::open(tmp.path()).unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn two_listings_persist_in_a_single_file() {
        let tmp = tempfile::tempdir().unwrap();
        let s1 = ListingStore::open(tmp.path()).unwrap();
        s1.insert("one".into(), sample_listing());
        s1.insert("two".into(), sample_listing());
        drop(s1);

        let s2 = ListingStore::open(tmp.path()).unwrap();
        let mut ids = s2.ids();
        ids.sort();
        assert_eq!(ids, vec!["one".to_string(), "two".to_string()]);
    }
}
