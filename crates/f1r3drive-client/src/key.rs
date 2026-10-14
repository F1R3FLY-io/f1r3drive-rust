//! secp256k1 key loading.
//!
//! The Java f1r3drive and f1r3node-rust CLI both accept either a 32-byte raw
//! hex private key (`--private-key`) or a path to a file containing one
//! (`--key-file`). We mirror that here. PEM/PKCS#8 support is deferred —
//! f1r3node-rust supports it (see `crypto/src/rust/signatures/secp256k1.rs:
//! parse_pem_file`) but the common dev flow uses raw hex.

use std::fs;
use std::path::Path;

use k256::ecdsa::SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::PublicKey;

use crate::error::ClientError;

/// A loaded secp256k1 key pair ready to sign deploys.
#[derive(Clone)]
pub struct KeyPair {
    pub(crate) signing_key: SigningKey,
    /// Uncompressed SEC1 encoding (0x04 || X || Y, 65 bytes). Matches the
    /// `deployer` field format expected by `DeployDataProto`.
    pub(crate) public_key_bytes: Vec<u8>,
}

impl KeyPair {
    /// Build a key pair from 32 raw bytes.
    pub fn from_private_bytes(bytes: &[u8]) -> Result<Self, ClientError> {
        if bytes.len() != 32 {
            return Err(ClientError::InvalidPrivateKey(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let signing_key = SigningKey::from_slice(bytes).map_err(|e| {
            ClientError::InvalidPrivateKey(format!("not a valid secp256k1 scalar: {e}"))
        })?;
        let public_key = PublicKey::from(signing_key.verifying_key());
        let public_key_bytes = public_key.to_encoded_point(false).as_bytes().to_vec();
        Ok(Self {
            signing_key,
            public_key_bytes,
        })
    }

    /// Parse a hex-encoded 32-byte secp256k1 private key, with or without a
    /// leading `0x`.
    pub fn from_private_hex(hex_str: &str) -> Result<Self, ClientError> {
        let trimmed = hex_str.trim().trim_start_matches("0x");
        let bytes = hex::decode(trimmed)
            .map_err(|e| ClientError::InvalidPrivateKey(format!("bad hex: {e}")))?;
        Self::from_private_bytes(&bytes)
    }

    /// Load a key pair from a file. The file may contain a hex key (whitespace
    /// is trimmed) or 32 raw bytes.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ClientError> {
        let path = path.as_ref();
        let bytes =
            fs::read(path).map_err(|e| ClientError::KeyFile(format!("{}: {e}", path.display())))?;
        if bytes.len() == 32 {
            return Self::from_private_bytes(&bytes);
        }
        // Try to parse as text (hex).
        let text = std::str::from_utf8(&bytes).map_err(|_| {
            ClientError::KeyFile(format!("{}: not hex and not 32 raw bytes", path.display()))
        })?;
        Self::from_private_hex(text)
    }

    /// Uncompressed SEC1-encoded public key (65 bytes, 0x04-prefixed).
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key_bytes
    }
}

impl std::fmt::Debug for KeyPair {
    // Hide the signing key.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public_key", &hex::encode(&self.public_key_bytes))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KNOWN_SK_HEX: &str = "4f8f5e4a6c7b1c7e3a9d8f2e1b0c5a4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b";

    #[test]
    fn from_hex_roundtrips() {
        let kp = KeyPair::from_private_hex(KNOWN_SK_HEX).unwrap();
        assert_eq!(kp.public_key_bytes().len(), 65);
        assert_eq!(kp.public_key_bytes()[0], 0x04);
    }

    #[test]
    fn from_hex_tolerates_0x_prefix_and_whitespace() {
        let kp = KeyPair::from_private_hex(&format!("  0x{KNOWN_SK_HEX}\n")).unwrap();
        assert_eq!(kp.public_key_bytes().len(), 65);
    }

    #[test]
    fn from_file_accepts_hex() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.hex");
        std::fs::write(&path, KNOWN_SK_HEX).unwrap();
        let kp = KeyPair::from_file(&path).unwrap();
        assert_eq!(kp.public_key_bytes().len(), 65);
    }

    #[test]
    fn from_file_accepts_raw_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.bin");
        let raw = hex::decode(KNOWN_SK_HEX).unwrap();
        std::fs::write(&path, &raw).unwrap();
        let kp = KeyPair::from_file(&path).unwrap();
        assert_eq!(kp.public_key_bytes().len(), 65);
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(KeyPair::from_private_bytes(&[0u8; 31]).is_err());
    }
}
