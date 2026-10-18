//! Error types for the crypto crate.
//!
//! Shaped so the mount-layer caller can treat any `CryptoError` as a
//! generic I/O failure (EIO) without surfacing cipher internals to
//! user-space FUSE replies — attacker-visible errors reveal nothing
//! more than "that blob didn't decrypt".

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("blob too short: {0} < {1}")]
    BlobTooShort(usize, usize),
    #[error("unknown envelope tag: {0:?}")]
    UnknownTag([u8; 4]),
    #[error("key fingerprint mismatch: on-chain hash does not match loaded key")]
    FingerprintMismatch,
    #[error(
        "AES-GCM decrypt failed (authentication tag mismatch, wrong key, or tampered ciphertext)"
    )]
    AeadDecrypt,
    #[error("ECIES decrypt failed (recipient key mismatch or malformed envelope)")]
    EciesDecrypt,
    #[error("header deserialise: {0}")]
    HeaderParse(String),
    #[error("padding corrupt: declared length {declared} > padded body {padded}")]
    PaddingCorrupt { declared: u64, padded: usize },
    #[error("keystore: {0}")]
    Keystore(#[from] std::io::Error),
    #[error("filename has interior NUL byte")]
    NulInFilename,
    #[error("secp256k1 pubkey must be 65 bytes uncompressed (0x04 || x || y); got {0}")]
    BadPubkeyLength(usize),
    #[error("secp256k1 private key must be 32 bytes; got {0}")]
    BadPrivkeyLength(usize),
}

pub type Result<T> = std::result::Result<T, CryptoError>;
