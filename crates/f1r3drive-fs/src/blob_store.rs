//! Blob storage abstraction for `ExtensionFs`.
//!
//! The mount layer stores encrypted envelopes under opaque on-chain
//! names. This module gives it a trait to speak against so slice 4
//! can land + unit-test the full create/read/readdir cycle without
//! a running shard; slice 5 provides the real Fs-agent-backed impl.
//!
//! Naming: encoded as `<prefix>_<cipher_name_hex>` where
//!
//! - `<prefix>` is the owner's 130-char pubkey hex. Flat storage
//!   with a filename prefix because the Fs agent's nested-dir
//!   support isn't wired yet; the daemon's virtual tree layer
//!   presents it as `/<pubkey>/<plaintext>`.
//! - `<cipher_name_hex>` is lowercase hex of the AES-GCM-encrypted
//!   plaintext filename, which lives inside the envelope header
//!   anyway. The *channel* name needs some string that's stable per
//!   file, so we use the hex of a hash of the ciphertext — same
//!   name every time we rewrite the same blob, different when the
//!   filename changes.
//!
//! The trait is intentionally minimal: four methods, no streaming,
//! no partial-byte access. ExtensionFs buffers each file in memory
//! until flush/release and then issues one `put`.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::extension_fs::PUBKEY_HEX_LEN;

/// Backend-agnostic blob store. Implementations encode the
/// `<prefix>_<cipher_name_hex>` naming internally.
///
/// Methods are synchronous so FUSE callbacks can call them directly.
/// Async impls (the slice-5 Fs-agent-backed one) `block_on` the
/// tokio runtime internally.
pub trait BlobStore: Send + Sync {
    /// Put a blob under `prefix` keyed by `channel_name`. Overwrites
    /// any existing entry at the same name.
    fn put(&self, prefix: &str, channel_name: &str, bytes: &[u8]) -> BlobResult<()>;

    /// Retrieve a blob by (prefix, channel_name). Returns `None` if
    /// absent.
    fn get(&self, prefix: &str, channel_name: &str) -> BlobResult<Option<Vec<u8>>>;

    /// List every channel name stored under `prefix`. Order is
    /// implementation-defined; the mount layer sorts for display.
    fn list(&self, prefix: &str) -> BlobResult<Vec<String>>;

    /// Delete a blob. No-op if absent.
    fn delete(&self, prefix: &str, channel_name: &str) -> BlobResult<()>;
}

#[derive(Debug, thiserror::Error)]
pub enum BlobError {
    #[error("prefix must be a {PUBKEY_HEX_LEN}-char lowercase pubkey hex; got {0:?}")]
    InvalidPrefix(String),
    #[error("channel name must be lowercase hex; got {0:?}")]
    InvalidChannelName(String),
    #[error("backend: {0}")]
    Backend(String),
}

pub type BlobResult<T> = std::result::Result<T, BlobError>;

/// Compose the on-chain name used by the Fs-agent-backed store from
/// the owner prefix + per-blob cipher-name hex.
pub fn compose_channel(prefix: &str, cipher_name_hex: &str) -> String {
    format!("{prefix}_{cipher_name_hex}")
}

/// Inverse of [`compose_channel`]. Returns `None` if the input
/// doesn't match the prefix.
pub fn strip_prefix<'a>(prefix: &str, channel: &'a str) -> Option<&'a str> {
    let full = format!("{prefix}_");
    channel.strip_prefix(&full)
}

/// Validate that a pubkey prefix matches the shape we store.
pub fn validate_prefix(prefix: &str) -> BlobResult<()> {
    if prefix.len() != PUBKEY_HEX_LEN
        || !prefix.chars().all(|c| c.is_ascii_hexdigit())
        || prefix != prefix.to_lowercase()
    {
        return Err(BlobError::InvalidPrefix(prefix.to_string()));
    }
    Ok(())
}

/// In-memory `BlobStore` for tests and for the slice-4 standalone
/// development path. Backed by a `HashMap<(prefix, channel), bytes>`.
#[derive(Debug, Default)]
pub struct InMemoryBlobStore {
    // Key = (prefix, channel_name). Value = raw envelope bytes.
    inner: RwLock<HashMap<(String, String), Vec<u8>>>,
}

impl InMemoryBlobStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl BlobStore for InMemoryBlobStore {
    fn put(&self, prefix: &str, channel_name: &str, bytes: &[u8]) -> BlobResult<()> {
        validate_prefix(prefix)?;
        self.inner.write().unwrap().insert(
            (prefix.to_string(), channel_name.to_string()),
            bytes.to_vec(),
        );
        Ok(())
    }

    fn get(&self, prefix: &str, channel_name: &str) -> BlobResult<Option<Vec<u8>>> {
        validate_prefix(prefix)?;
        Ok(self
            .inner
            .read()
            .unwrap()
            .get(&(prefix.to_string(), channel_name.to_string()))
            .cloned())
    }

    fn list(&self, prefix: &str) -> BlobResult<Vec<String>> {
        validate_prefix(prefix)?;
        let g = self.inner.read().unwrap();
        let out: Vec<String> = g
            .keys()
            .filter(|(p, _)| p == prefix)
            .map(|(_, c)| c.clone())
            .collect();
        Ok(out)
    }

    fn delete(&self, prefix: &str, channel_name: &str) -> BlobResult<()> {
        validate_prefix(prefix)?;
        self.inner
            .write()
            .unwrap()
            .remove(&(prefix.to_string(), channel_name.to_string()));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(seed: u8) -> String {
        let mut s = String::from("04");
        for _ in 0..64 {
            s.push_str(&format!("{seed:02x}"));
        }
        s.truncate(PUBKEY_HEX_LEN);
        s
    }

    #[test]
    fn put_get_round_trips() {
        let s = InMemoryBlobStore::new();
        let p = pk(0xab);
        s.put(&p, "abcd", b"hello").unwrap();
        assert_eq!(s.get(&p, "abcd").unwrap(), Some(b"hello".to_vec()));
    }

    #[test]
    fn get_missing_is_none() {
        let s = InMemoryBlobStore::new();
        let p = pk(0xab);
        assert_eq!(s.get(&p, "nope").unwrap(), None);
    }

    #[test]
    fn list_scopes_to_prefix() {
        let s = InMemoryBlobStore::new();
        let p1 = pk(0xab);
        let p2 = pk(0xcd);
        s.put(&p1, "a", b"1").unwrap();
        s.put(&p1, "b", b"2").unwrap();
        s.put(&p2, "c", b"3").unwrap();
        let mut l1 = s.list(&p1).unwrap();
        l1.sort();
        assert_eq!(l1, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(s.list(&p2).unwrap(), vec!["c".to_string()]);
    }

    #[test]
    fn delete_is_idempotent() {
        let s = InMemoryBlobStore::new();
        let p = pk(0xab);
        s.put(&p, "x", b"y").unwrap();
        s.delete(&p, "x").unwrap();
        s.delete(&p, "x").unwrap(); // no-op
        assert!(s.get(&p, "x").unwrap().is_none());
    }

    #[test]
    fn put_overwrites() {
        let s = InMemoryBlobStore::new();
        let p = pk(0xab);
        s.put(&p, "k", b"first").unwrap();
        s.put(&p, "k", b"second").unwrap();
        assert_eq!(s.get(&p, "k").unwrap(), Some(b"second".to_vec()));
    }

    #[test]
    fn invalid_prefix_rejected() {
        let s = InMemoryBlobStore::new();
        assert!(matches!(
            s.put("too-short", "k", b""),
            Err(BlobError::InvalidPrefix(_))
        ));
        // 130 hex chars but with uppercase — the validator insists on
        // lowercase so this must fail.
        assert!(matches!(
            s.get(&"AB".repeat(65), "k"),
            Err(BlobError::InvalidPrefix(_))
        ));
        // 130 chars but one isn't a hex digit.
        let mut non_hex = "4".repeat(129);
        non_hex.push('g');
        assert!(matches!(
            s.get(&non_hex, "k"),
            Err(BlobError::InvalidPrefix(_))
        ));
    }

    #[test]
    fn compose_strip_round_trips() {
        let p = pk(0xab);
        let composed = compose_channel(&p, "deadbeef");
        assert_eq!(strip_prefix(&p, &composed), Some("deadbeef"));
    }

    #[test]
    fn strip_prefix_rejects_mismatch() {
        let p = pk(0xab);
        let p2 = pk(0xcd);
        let composed = compose_channel(&p, "deadbeef");
        assert_eq!(strip_prefix(&p2, &composed), None);
    }
}
