//! Local identity bootstrap for `f1r3drive-rust` extension mode.
//!
//! Owns the state under `<state_dir>/`:
//!
//! ```text
//! <state_dir>/
//! ├── identity.key   64 hex chars of secp256k1 private key, chmod 0600
//! └── identity.pub   130 hex chars of uncompressed pubkey (04 || x || y)
//! ```
//!
//! Load-or-create: on first run the daemon generates a fresh key,
//! writes both files atomically, and returns an `Identity`. On
//! subsequent runs, it loads from disk and verifies that the pubkey
//! file matches what the private key derives to (so a mix-and-match
//! across `.f1r3drive/` directories is caught at startup).
//!
//! The pubkey hex IS the user's folder name in extension-mode mounts;
//! see `docs/architecture/ADR-0002-extension-design.md`.
//!
//! The private-key file layout is identical to what
//! `f1r3drive_client::KeyPair::from_file` already consumes, so the
//! existing `--key-file` flag on the daemon reads it directly — no
//! separate file format for extension mode.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use rand::{rngs::OsRng, TryRngCore};
use thiserror::Error;

use f1r3drive_client::KeyPair;
use f1r3drive_wallet::{AddressError, RevAddress};

pub const IDENTITY_KEY_FILE: &str = "identity.key";
pub const IDENTITY_PUB_FILE: &str = "identity.pub";

/// The user's local identity. The pubkey hex is also the directory
/// name under which the user's files land in extension-mode mounts.
pub struct Identity {
    keypair: KeyPair,
    pubkey_hex: String,
    rev_address: RevAddress,
    state_dir: PathBuf,
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("state dir {0:?}: {1}")]
    StateDir(PathBuf, #[source] io::Error),
    #[error("read {0:?}: {1}")]
    ReadFile(PathBuf, #[source] io::Error),
    #[error("write {0:?}: {1}")]
    WriteFile(PathBuf, #[source] io::Error),
    #[error("private key parse: {0}")]
    KeyParse(String),
    #[error("stored pubkey {stored:?} doesn't match pubkey derived from private key {derived:?}")]
    PubkeyMismatch { stored: String, derived: String },
    #[error("pubkey hex: {0}")]
    PubkeyHex(String),
    #[error("REV address derivation: {0}")]
    RevAddress(#[from] AddressError),
}

type Result<T> = std::result::Result<T, IdentityError>;

impl Identity {
    /// Load the identity from `<state_dir>/`, creating a fresh one
    /// if either file is missing. Idempotent — safe to call on
    /// every daemon start.
    pub fn load_or_create(state_dir: impl AsRef<Path>) -> Result<Self> {
        let state_dir = state_dir.as_ref().to_path_buf();
        ensure_state_dir(&state_dir)?;

        let key_path = state_dir.join(IDENTITY_KEY_FILE);
        let pub_path = state_dir.join(IDENTITY_PUB_FILE);

        match (key_path.exists(), pub_path.exists()) {
            (true, true) => load_existing(&state_dir, &key_path, &pub_path),
            (false, false) => create_fresh(&state_dir, &key_path, &pub_path),
            // Half-written state. The pubkey can always be re-derived
            // from the private key, so if the key is present but the
            // pub file is missing, regenerate the pub. If the pub is
            // present but the key is missing, bail — we can't recover
            // the private key, and silently generating a new one
            // would clobber whatever folder the user already owns on
            // chain.
            (true, false) => {
                let kp = load_keypair(&key_path)?;
                let pubkey_hex = hex::encode(kp.public_key_bytes());
                write_file_mode(&pub_path, pubkey_hex.as_bytes(), 0o644)?;
                tracing::info!(
                    path = %pub_path.display(),
                    "identity.pub was missing; regenerated from identity.key"
                );
                let rev_address = RevAddress::from_public_key_bytes(kp.public_key_bytes())
                    .map_err(IdentityError::from)?;
                Ok(Self {
                    keypair: kp,
                    pubkey_hex,
                    rev_address,
                    state_dir,
                })
            }
            (false, true) => Err(IdentityError::KeyParse(format!(
                "{} is present but {} is missing — refusing to generate a new private key \
                 since we can't recover the one that produced {}; move or restore the private key \
                 file first",
                pub_path.display(),
                key_path.display(),
                pub_path.display(),
            ))),
        }
    }

    /// Convenience: load-or-create under `$HOME/.f1r3drive/`.
    pub fn load_or_create_default() -> Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| IdentityError::KeyParse("$HOME is unset".into()))?;
        Self::load_or_create(home.join(".f1r3drive"))
    }

    pub fn keypair(&self) -> &KeyPair {
        &self.keypair
    }

    /// 65-byte uncompressed secp256k1 pubkey (`0x04 || x || y`).
    pub fn public_key_bytes(&self) -> &[u8] {
        self.keypair.public_key_bytes()
    }

    /// 130-char lowercase hex of the pubkey. This is the user's
    /// folder name in extension-mode mounts.
    pub fn pubkey_hex(&self) -> &str {
        &self.pubkey_hex
    }

    pub fn rev_address(&self) -> &RevAddress {
        &self.rev_address
    }

    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    pub fn identity_key_path(&self) -> PathBuf {
        self.state_dir.join(IDENTITY_KEY_FILE)
    }
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never dump the keypair — the `KeyPair` type carries the
        // private scalar.
        f.debug_struct("Identity")
            .field("pubkey_hex", &self.pubkey_hex)
            .field("rev_address", &self.rev_address.to_base58())
            .field("state_dir", &self.state_dir)
            .finish()
    }
}

fn ensure_state_dir(state_dir: &Path) -> Result<()> {
    if !state_dir.exists() {
        fs::create_dir_all(state_dir)
            .map_err(|e| IdentityError::StateDir(state_dir.to_path_buf(), e))?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o700);
        fs::set_permissions(state_dir, perms)
            .map_err(|e| IdentityError::StateDir(state_dir.to_path_buf(), e))?;
    }
    Ok(())
}

fn load_existing(state_dir: &Path, key_path: &Path, pub_path: &Path) -> Result<Identity> {
    let kp = load_keypair(key_path)?;
    let stored_pub = fs::read_to_string(pub_path)
        .map_err(|e| IdentityError::ReadFile(pub_path.to_path_buf(), e))?
        .trim()
        .to_string();
    let derived_pub = hex::encode(kp.public_key_bytes());
    if stored_pub.to_lowercase() != derived_pub {
        return Err(IdentityError::PubkeyMismatch {
            stored: stored_pub,
            derived: derived_pub,
        });
    }
    let rev_address =
        RevAddress::from_public_key_bytes(kp.public_key_bytes()).map_err(IdentityError::from)?;
    Ok(Identity {
        keypair: kp,
        pubkey_hex: derived_pub,
        rev_address,
        state_dir: state_dir.to_path_buf(),
    })
}

fn create_fresh(state_dir: &Path, key_path: &Path, pub_path: &Path) -> Result<Identity> {
    // Fill 32 random bytes from the OS CSPRNG. `k256`'s own
    // `SigningKey::random` wants an older `rand_core::CryptoRngCore`
    // than `rand 0.9` currently provides, so we go through
    // `KeyPair::from_private_bytes` instead — it rejects
    // out-of-range scalars just like `SigningKey::random` would.
    let mut priv_bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut priv_bytes)
        .map_err(|e| IdentityError::KeyParse(format!("OS CSPRNG: {e}")))?;
    let kp = KeyPair::from_private_bytes(&priv_bytes)
        .map_err(|e| IdentityError::KeyParse(e.to_string()))?;
    let priv_hex = hex::encode(priv_bytes);
    let pub_hex = hex::encode(kp.public_key_bytes());

    write_file_mode(key_path, priv_hex.as_bytes(), 0o600)?;
    write_file_mode(pub_path, pub_hex.as_bytes(), 0o644)?;
    tracing::info!(
        state_dir = %state_dir.display(),
        pubkey = %pub_hex,
        "fresh identity generated"
    );
    let rev_address =
        RevAddress::from_public_key_bytes(kp.public_key_bytes()).map_err(IdentityError::from)?;
    Ok(Identity {
        keypair: kp,
        pubkey_hex: pub_hex,
        rev_address,
        state_dir: state_dir.to_path_buf(),
    })
}

fn load_keypair(path: &Path) -> Result<KeyPair> {
    KeyPair::from_file(path).map_err(|e| IdentityError::KeyParse(e.to_string()))
}

fn write_file_mode(path: &Path, bytes: &[u8], _mode: u32) -> Result<()> {
    // Atomic write via tmp-sibling-rename so a crash never leaves a
    // half-written key/pub file.
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|e| IdentityError::WriteFile(tmp.clone(), e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(_mode);
        fs::set_permissions(&tmp, perms).map_err(|e| IdentityError::WriteFile(tmp.clone(), e))?;
    }
    fs::rename(&tmp, path).map_err(|e| IdentityError::WriteFile(path.to_path_buf(), e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_identity_creates_both_files() {
        let tmp = tempfile::tempdir().unwrap();
        let id = Identity::load_or_create(tmp.path()).unwrap();
        assert_eq!(id.pubkey_hex().len(), 130); // 65 bytes = 130 hex
        assert!(id.pubkey_hex().chars().all(|c| c.is_ascii_hexdigit()));
        assert!(tmp.path().join(IDENTITY_KEY_FILE).exists());
        assert!(tmp.path().join(IDENTITY_PUB_FILE).exists());
    }

    #[test]
    fn pubkey_file_contents_match_derived() {
        let tmp = tempfile::tempdir().unwrap();
        let id = Identity::load_or_create(tmp.path()).unwrap();
        let stored = fs::read_to_string(tmp.path().join(IDENTITY_PUB_FILE))
            .unwrap()
            .trim()
            .to_string();
        assert_eq!(stored, id.pubkey_hex());
    }

    #[test]
    fn load_round_trips_a_second_call() {
        let tmp = tempfile::tempdir().unwrap();
        let first = Identity::load_or_create(tmp.path()).unwrap();
        let second = Identity::load_or_create(tmp.path()).unwrap();
        assert_eq!(first.pubkey_hex(), second.pubkey_hex());
        assert_eq!(
            first.rev_address().to_base58(),
            second.rev_address().to_base58()
        );
    }

    #[test]
    fn tampered_pubkey_file_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let _ = Identity::load_or_create(tmp.path()).unwrap();
        // Replace with a different pubkey derived from a fresh random key.
        let mut other_priv = [0u8; 32];
        OsRng.try_fill_bytes(&mut other_priv).unwrap();
        let other = KeyPair::from_private_bytes(&other_priv).unwrap();
        fs::write(
            tmp.path().join(IDENTITY_PUB_FILE),
            hex::encode(other.public_key_bytes()),
        )
        .unwrap();
        assert!(matches!(
            Identity::load_or_create(tmp.path()),
            Err(IdentityError::PubkeyMismatch { .. }),
        ));
    }

    #[test]
    fn missing_pub_regenerates_from_key() {
        let tmp = tempfile::tempdir().unwrap();
        let first = Identity::load_or_create(tmp.path()).unwrap();
        fs::remove_file(tmp.path().join(IDENTITY_PUB_FILE)).unwrap();
        let second = Identity::load_or_create(tmp.path()).unwrap();
        assert_eq!(first.pubkey_hex(), second.pubkey_hex());
    }

    #[test]
    fn missing_key_with_present_pub_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let _ = Identity::load_or_create(tmp.path()).unwrap();
        fs::remove_file(tmp.path().join(IDENTITY_KEY_FILE)).unwrap();
        assert!(matches!(
            Identity::load_or_create(tmp.path()),
            Err(IdentityError::KeyParse(_)),
        ));
    }

    #[test]
    fn two_fresh_identities_differ() {
        let a = tempfile::tempdir().unwrap();
        let b = tempfile::tempdir().unwrap();
        let ida = Identity::load_or_create(a.path()).unwrap();
        let idb = Identity::load_or_create(b.path()).unwrap();
        assert_ne!(ida.pubkey_hex(), idb.pubkey_hex());
    }

    #[test]
    #[cfg(unix)]
    fn key_file_permissions_are_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let id = Identity::load_or_create(tmp.path()).unwrap();
        let perms = fs::metadata(id.identity_key_path()).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[test]
    #[cfg(unix)]
    fn state_dir_permissions_are_0700() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let _ = Identity::load_or_create(tmp.path()).unwrap();
        let perms = fs::metadata(tmp.path()).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o700);
    }

    #[test]
    fn identity_debug_omits_private_key() {
        let tmp = tempfile::tempdir().unwrap();
        let id = Identity::load_or_create(tmp.path()).unwrap();
        let dbg = format!("{id:?}");
        // Shouldn't contain anything that could decode to the private key.
        // The pubkey hex is intentionally present.
        assert!(dbg.contains(id.pubkey_hex()));
        assert!(!dbg.contains("private") && !dbg.contains("Private"));
    }

    #[test]
    fn pubkey_hex_matches_folder_name_shape() {
        let tmp = tempfile::tempdir().unwrap();
        let id = Identity::load_or_create(tmp.path()).unwrap();
        // Design: 130-char lowercase hex, starts with "04" (uncompressed tag).
        assert_eq!(id.pubkey_hex().len(), 130);
        assert!(id.pubkey_hex().starts_with("04"));
        assert_eq!(id.pubkey_hex(), id.pubkey_hex().to_lowercase());
    }

    #[test]
    fn rev_address_derivation_matches_wallet_crate() {
        let tmp = tempfile::tempdir().unwrap();
        let id = Identity::load_or_create(tmp.path()).unwrap();
        let via_wallet = RevAddress::from_public_key_bytes(id.public_key_bytes()).unwrap();
        assert_eq!(id.rev_address(), &via_wallet);
    }
}
