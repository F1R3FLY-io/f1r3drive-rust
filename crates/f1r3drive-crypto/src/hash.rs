//! Blake2b-256 key fingerprints.
//!
//! The SELF envelope format carries `blake2b256(K)` as a 32-byte
//! index so the owner's local daemon can look up K in the keystore
//! without trial-decrypting every candidate. Blake2b-256 is also
//! what the rest of the stack uses (deploy signing hash, REV
//! address checksum), so this stays single-source for crypto hash
//! choice.

use blake2::{
    digest::{consts::U32, Digest},
    Blake2b,
};

/// Length of the fingerprint in bytes. Blake2b-256.
pub const FINGERPRINT_LEN: usize = 32;

/// `blake2b256(input)` — 32 bytes.
pub fn key_fingerprint(input: &[u8]) -> [u8; FINGERPRINT_LEN] {
    let mut h = Blake2b::<U32>::new();
    h.update(input);
    let out = h.finalize();
    let mut arr = [0u8; FINGERPRINT_LEN];
    arr.copy_from_slice(&out);
    arr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_deterministic() {
        let a = key_fingerprint(b"hello");
        let b = key_fingerprint(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn different_inputs_different_hashes() {
        assert_ne!(key_fingerprint(b"a"), key_fingerprint(b"b"));
    }

    #[test]
    fn fingerprint_length_is_32() {
        assert_eq!(key_fingerprint(b"any input").len(), 32);
    }
}
