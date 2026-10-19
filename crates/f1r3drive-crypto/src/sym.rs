//! AES-256-GCM symmetric wrapping.
//!
//! Format of a sealed buffer: `12-byte nonce || ciphertext || 16-byte GCM tag`.
//! The nonce is random per encrypt and prepended so the opener needs
//! only the key.
//!
//! AEAD is used without associated-data in this module; callers that
//! want to bind context (envelope tag, filename, etc.) prepend it to
//! the plaintext before `seal`. The envelope module (which composes
//! this) uses that pattern.

// `aes-gcm` 0.10 and `blake2` pull different `generic-array` majors
// via `digest`. The resulting `from_slice` is marked deprecated by
// one copy and not the other; the deprecation is cosmetic — the
// generated code is identical — so we silence it at the call sites
// below. Removing on upgrade to aes-gcm 0.11.
#[allow(deprecated)]
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use rand::{rngs::OsRng as RandOsRng, TryRngCore};

use crate::error::{CryptoError, Result};

pub const AES_KEY_LEN: usize = 32;
pub const GCM_NONCE_LEN: usize = 12;
pub const GCM_TAG_LEN: usize = 16;

/// 256-bit symmetric key. Opaque wrapper around a `[u8; 32]` so the
/// envelope + keystore layers can't accidentally hand `Vec<u8>` of
/// the wrong length to the AEAD.
#[derive(Clone, Copy)]
pub struct SymKey(pub [u8; AES_KEY_LEN]);

impl SymKey {
    pub fn as_bytes(&self) -> &[u8; AES_KEY_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for SymKey {
    // Don't dump raw bytes to logs.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SymKey(..redacted..)")
    }
}

/// Fresh random key via the OS CSPRNG.
pub fn generate_key() -> SymKey {
    let mut k = [0u8; AES_KEY_LEN];
    RandOsRng
        .try_fill_bytes(&mut k)
        .expect("OsRng is infallible on supported platforms");
    SymKey(k)
}

/// AES-GCM encrypt. Returns `nonce || ciphertext || tag`.
pub fn seal(key: &SymKey, plaintext: &[u8]) -> Vec<u8> {
    #[allow(deprecated)]
    let aead = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ct = aead
        .encrypt(&nonce, plaintext)
        .expect("Aes256Gcm::encrypt is infallible on in-memory input");
    let mut out = Vec::with_capacity(GCM_NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// AES-GCM decrypt. Expects `nonce || ciphertext || tag`.
pub fn open(key: &SymKey, sealed: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < GCM_NONCE_LEN + GCM_TAG_LEN {
        return Err(CryptoError::BlobTooShort(
            sealed.len(),
            GCM_NONCE_LEN + GCM_TAG_LEN,
        ));
    }
    let (nonce_bytes, ct) = sealed.split_at(GCM_NONCE_LEN);
    #[allow(deprecated)]
    let aead = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key.as_bytes()));
    #[allow(deprecated)]
    let nonce = Nonce::from_slice(nonce_bytes);
    aead.decrypt(nonce, ct)
        .map_err(|_| CryptoError::AeadDecrypt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_key_is_random() {
        let k1 = generate_key();
        let k2 = generate_key();
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    #[test]
    fn seal_open_round_trips() {
        let k = generate_key();
        let pt = b"hello, world";
        let ct = seal(&k, pt);
        assert_eq!(open(&k, &ct).unwrap(), pt);
    }

    #[test]
    fn different_nonce_each_seal() {
        let k = generate_key();
        let pt = b"same plaintext";
        let a = seal(&k, pt);
        let b = seal(&k, pt);
        // Overwhelmingly likely to differ due to random nonce.
        assert_ne!(a, b);
        assert_eq!(open(&k, &a).unwrap(), pt);
        assert_eq!(open(&k, &b).unwrap(), pt);
    }

    #[test]
    fn open_with_wrong_key_fails() {
        let k1 = generate_key();
        let k2 = generate_key();
        let ct = seal(&k1, b"secret");
        assert!(matches!(open(&k2, &ct), Err(CryptoError::AeadDecrypt)));
    }

    #[test]
    fn open_detects_tamper() {
        let k = generate_key();
        let mut ct = seal(&k, b"secret");
        // Flip one byte in the ciphertext region.
        let last = ct.len() - 1;
        ct[last] ^= 1;
        assert!(matches!(open(&k, &ct), Err(CryptoError::AeadDecrypt)));
    }

    #[test]
    fn open_rejects_too_short_input() {
        let k = generate_key();
        assert!(matches!(
            open(&k, &[]),
            Err(CryptoError::BlobTooShort(0, _))
        ));
        assert!(matches!(
            open(&k, &[0; 10]),
            Err(CryptoError::BlobTooShort(10, _))
        ));
    }

    #[test]
    fn symkey_debug_doesnt_leak() {
        let k = generate_key();
        let s = format!("{:?}", k);
        assert_eq!(s, "SymKey(..redacted..)");
    }
}
