//! In-process registry of minted listings.
//!
//! Slice 7 scope: daemon-local, non-persistent. Each listing records
//! who dropped the file, which template produced it, and the parsed
//! spec. The daemon enumerates this store on `readdir /` so uuid
//! folders appear next to pubkey folders.
//!
//! Slice 8 will move this to on-chain state so purchases + REV
//! transfers reach the right account across daemon restarts.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::contract_template::ListingSpec;

/// A single active listing. Owner is the uncompressed pubkey hex of
/// the user who dropped the file into their own `/<me>/<template>/`
/// subfolder — the one who'll receive REV on purchase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    pub owner_pubkey_hex: String,
    pub template_name: &'static str,
    pub spec: ListingSpec,
}

/// Thread-safe listing table. Operations are O(1) + a `RwLock` hop;
/// readdir on root is read-mostly so we favour read concurrency.
#[derive(Debug, Default)]
pub struct ListingStore {
    inner: RwLock<HashMap<String, Listing>>,
}

impl ListingStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, id: String, listing: Listing) {
        self.inner.write().unwrap().insert(id, listing);
    }

    pub fn get(&self, id: &str) -> Option<Listing> {
        self.inner.read().unwrap().get(id).cloned()
    }

    pub fn remove(&self, id: &str) -> Option<Listing> {
        self.inner.write().unwrap().remove(id)
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_listing() -> Listing {
        Listing {
            owner_pubkey_hex: "04".to_string() + &"ab".repeat(64),
            template_name: "Paid transfer",
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
}
