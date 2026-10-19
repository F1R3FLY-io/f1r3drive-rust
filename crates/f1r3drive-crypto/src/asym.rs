//! ECIES over secp256k1 for wrapping a 32-byte symmetric key.
//!
//! Uses the `ecies` crate: ephemeral keypair → ECDH with the
//! recipient's static pubkey → HKDF → AES-256-GCM over the payload.
//! Output format (per the crate's layout):
//!
//!   65 bytes ephemeral pubkey (uncompressed) || 16-byte GCM tag || ciphertext
//!
//! The recipient's pubkey is 65 bytes uncompressed (`0x04 || x || y`),
//! same encoding as our identity folders use. The private key is 32
//! raw bytes (same as `f1r3drive-client::KeyPair`).
//!
//! This module is thin wrapping to normalize errors; the `ecies` crate
//! does the real work.

use crate::error::{CryptoError, Result};

/// Wrap `symmetric_key` so only the holder of the matching 32-byte
/// private key can unwrap it.
///
/// `recipient_pubkey` must be the 65-byte uncompressed secp256k1
/// pubkey (`0x04 || x || y`). The ephemeral ECDH key is generated
/// fresh per call so repeated wraps of the same key for the same
/// recipient produce different ciphertexts.
pub fn ecies_wrap(recipient_pubkey: &[u8], symmetric_key: &[u8]) -> Result<Vec<u8>> {
    if recipient_pubkey.len() != 65 {
        return Err(CryptoError::BadPubkeyLength(recipient_pubkey.len()));
    }
    ecies::encrypt(recipient_pubkey, symmetric_key).map_err(|_| CryptoError::EciesDecrypt)
}

/// Unwrap. Returns the recovered symmetric-key bytes.
///
/// `my_private_key` must be the 32-byte raw secp256k1 scalar — same
/// shape as what `KeyPair::from_private_bytes` consumes.
pub fn ecies_unwrap(my_private_key: &[u8], wrapped: &[u8]) -> Result<Vec<u8>> {
    if my_private_key.len() != 32 {
        return Err(CryptoError::BadPrivkeyLength(my_private_key.len()));
    }
    ecies::decrypt(my_private_key, wrapped).map_err(|_| CryptoError::EciesDecrypt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ecies::utils::generate_keypair;

    fn fresh_keypair() -> (Vec<u8>, Vec<u8>) {
        let (sk, pk) = generate_keypair();
        (sk.serialize().to_vec(), pk.serialize().to_vec())
    }

    #[test]
    fn wrap_unwrap_round_trips() {
        let (sk, pk) = fresh_keypair();
        let key = [0x42u8; 32];
        let wrapped = ecies_wrap(&pk, &key).unwrap();
        let recovered = ecies_unwrap(&sk, &wrapped).unwrap();
        assert_eq!(recovered, key);
    }

    #[test]
    fn fresh_ephemerals_make_wraps_differ() {
        let (_, pk) = fresh_keypair();
        let key = [0x11u8; 32];
        let a = ecies_wrap(&pk, &key).unwrap();
        let b = ecies_wrap(&pk, &key).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_private_key_rejected() {
        let (_sk1, pk1) = fresh_keypair();
        let (sk2, _pk2) = fresh_keypair();
        let key = [0x33u8; 32];
        let wrapped = ecies_wrap(&pk1, &key).unwrap();
        assert!(matches!(
            ecies_unwrap(&sk2, &wrapped),
            Err(CryptoError::EciesDecrypt)
        ));
    }

    #[test]
    fn bad_pubkey_length_errors() {
        let bad = vec![0u8; 32];
        assert!(matches!(
            ecies_wrap(&bad, &[0u8; 32]),
            Err(CryptoError::BadPubkeyLength(32))
        ));
    }

    #[test]
    fn bad_privkey_length_errors() {
        let (_, pk) = fresh_keypair();
        let wrapped = ecies_wrap(&pk, &[0u8; 32]).unwrap();
        assert!(matches!(
            ecies_unwrap(&[0u8; 16], &wrapped),
            Err(CryptoError::BadPrivkeyLength(16))
        ));
    }

    #[test]
    fn tamper_detection_via_aead() {
        let (sk, pk) = fresh_keypair();
        let key = [0x55u8; 32];
        let mut wrapped = ecies_wrap(&pk, &key).unwrap();
        // Flip a byte in the AEAD body (after the 65-byte ephemeral pubkey).
        let last = wrapped.len() - 1;
        wrapped[last] ^= 1;
        assert!(matches!(
            ecies_unwrap(&sk, &wrapped),
            Err(CryptoError::EciesDecrypt)
        ));
    }
}
