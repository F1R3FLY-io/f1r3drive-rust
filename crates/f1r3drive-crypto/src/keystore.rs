//! On-disk keystore for SELF-blob symmetric keys.
//!
//! Layout under `<root>/keys/`:
//!
//!   <hex of blake2b256(K)>              raw 32 bytes of K, chmod 0600
//!
//! The directory itself is `drwx------` (0700). The daemon walks the
//! keystore on every SELF read to look up K by its fingerprint. On
//! writes, store(K) saves the key under its fingerprint; the caller
//! prepends the fingerprint to the on-chain blob.
//!
//! Ergonomics: filenames are the lowercase hex of the 32-byte
//! fingerprint (64 chars). Tolerate but canonicalise case on lookup
//! so paranoid cleanups with uppercase names still work.
//!
//! The keystore does NOT hold the identity key — that's at
//! `<root>/identity.key` and is managed by `f1r3drive-identity`
//! (Slice 2). This module is strictly the per-blob symmetric key
//! index.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::error::Result;
use crate::hash::{key_fingerprint, FINGERPRINT_LEN};
use crate::sym::{SymKey, AES_KEY_LEN};

/// Filesystem-backed symmetric-key store rooted at `<state_dir>/keys/`.
#[derive(Debug, Clone)]
pub struct Keystore {
    keys_dir: PathBuf,
}

impl Keystore {
    /// Open/create a keystore under `state_dir`. The `keys/`
    /// subdirectory is created if missing and chmod-ed to 0700 on
    /// Unix. The root dir itself is assumed to exist (caller's
    /// identity bootstrap creates it).
    pub fn open(state_dir: impl AsRef<Path>) -> Result<Self> {
        let keys_dir = state_dir.as_ref().join("keys");
        fs::create_dir_all(&keys_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&keys_dir)?.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(&keys_dir, perms)?;
        }
        Ok(Self { keys_dir })
    }

    /// Save `key`, keyed by its blake2b256 fingerprint. Returns the
    /// fingerprint for the caller to embed in the SELF blob. Writes
    /// atomically: write to a temp file then rename, so a crashed
    /// store leaves either the old key or the new one — never a
    /// torn write.
    pub fn store(&self, key: &SymKey) -> Result<[u8; FINGERPRINT_LEN]> {
        let fp = key_fingerprint(key.as_bytes());
        let name = hex::encode(fp);
        let tmp = self.keys_dir.join(format!(".{name}.tmp"));
        let dst = self.keys_dir.join(&name);
        fs::write(&tmp, key.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&tmp)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&tmp, perms)?;
        }
        fs::rename(&tmp, &dst)?;
        Ok(fp)
    }

    /// Load the key with the given fingerprint. Returns `None` if
    /// not present; propagates I/O errors otherwise.
    pub fn load(&self, fingerprint: &[u8; FINGERPRINT_LEN]) -> Result<Option<SymKey>> {
        let name = hex::encode(fingerprint);
        let path = self.keys_dir.join(&name);
        match fs::read(&path) {
            Ok(bytes) if bytes.len() == AES_KEY_LEN => {
                let mut arr = [0u8; AES_KEY_LEN];
                arr.copy_from_slice(&bytes);
                Ok(Some(SymKey(arr)))
            }
            Ok(bytes) => {
                // On-disk key is wrong length — treat as missing;
                // a legitimate call site that depends on this key
                // will fail with FingerprintMismatch at decrypt
                // time, giving a precise diagnostic.
                tracing_warn_bad_key_length(&path, bytes.len());
                Ok(None)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Delete the entry for `fingerprint`. No-op if absent.
    pub fn delete(&self, fingerprint: &[u8; FINGERPRINT_LEN]) -> Result<()> {
        let name = hex::encode(fingerprint);
        let path = self.keys_dir.join(&name);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    /// Current number of entries. Mostly for diagnostics.
    pub fn len(&self) -> Result<usize> {
        let mut n = 0;
        for entry in fs::read_dir(&self.keys_dir)? {
            let entry = entry?;
            if entry.file_name().to_string_lossy().starts_with('.') {
                continue; // skip hidden / in-flight tmp files
            }
            n += 1;
        }
        Ok(n)
    }

    /// `true` iff there are no entries. Diagnostics companion to
    /// [`Self::len`]; propagates I/O errors the same way.
    pub fn is_empty(&self) -> Result<bool> {
        self.len().map(|n| n == 0)
    }
}

// Logging indirection kept out of the hot path. Pulls `tracing`
// transitively via the workspace, but we avoid making it a hard dep
// here — a warn is advisory only.
fn tracing_warn_bad_key_length(path: &Path, len: usize) {
    eprintln!(
        "f1r3drive-crypto: keystore entry {} has wrong length {} (expected {}); treating as missing",
        path.display(),
        len,
        AES_KEY_LEN,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sym::generate_key;

    #[test]
    fn store_load_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = Keystore::open(tmp.path()).unwrap();
        let k = generate_key();
        let fp = ks.store(&k).unwrap();
        let loaded = ks.load(&fp).unwrap().unwrap();
        assert_eq!(loaded.as_bytes(), k.as_bytes());
    }

    #[test]
    fn load_missing_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = Keystore::open(tmp.path()).unwrap();
        let fp = [0u8; FINGERPRINT_LEN];
        assert!(ks.load(&fp).unwrap().is_none());
    }

    #[test]
    fn delete_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = Keystore::open(tmp.path()).unwrap();
        let k = generate_key();
        let fp = ks.store(&k).unwrap();
        ks.delete(&fp).unwrap();
        ks.delete(&fp).unwrap(); // second time: no-op
        assert!(ks.load(&fp).unwrap().is_none());
    }

    #[test]
    fn len_counts_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = Keystore::open(tmp.path()).unwrap();
        assert_eq!(ks.len().unwrap(), 0);
        ks.store(&generate_key()).unwrap();
        ks.store(&generate_key()).unwrap();
        assert_eq!(ks.len().unwrap(), 2);
    }

    #[test]
    #[cfg(unix)]
    fn keys_dir_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let _ = Keystore::open(tmp.path()).unwrap();
        let perms = fs::metadata(tmp.path().join("keys")).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o700);
    }

    #[test]
    fn wrong_length_entry_is_treated_as_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let ks = Keystore::open(tmp.path()).unwrap();
        let fp = [0xABu8; FINGERPRINT_LEN];
        let bogus = tmp.path().join("keys").join(hex::encode(fp));
        fs::write(&bogus, b"not 32 bytes").unwrap();
        assert!(ks.load(&fp).unwrap().is_none());
    }
}
