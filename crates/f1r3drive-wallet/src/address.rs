//! REV address derivation and parsing.
//!
//! Replicates `rholang/src/rust/interpreter/util/vault_address.rs` on
//! f1r3node-rust (which in turn mirrors
//! `rholang/.../util/VaultAddress.scala`). The algorithm is:
//!
//! 1. Drop the uncompressed-pubkey tag byte (`0x04`), leaving 64 bytes
//!    of `(x || y)`.
//! 2. Keccak256 of those 64 bytes; take the last 20 bytes = Ethereum
//!    address of the key.
//! 3. Keccak256 of the 20-byte ETH address = `key_hash` (32 bytes).
//! 4. Prefix is 4 bytes: COIN_ID (`00 00 00`) || VERSION (`00`).
//! 5. Payload = prefix || key_hash (36 bytes).
//! 6. Checksum = first 4 bytes of Blake2b-256(payload).
//! 7. Address bytes = payload || checksum (40 bytes).
//! 8. Base58-encode.
//!
//! The chain reads `rev_address` strings in exactly this encoding,
//! so staying byte-identical with f1r3node-rust is a hard constraint.
//! A regression test pins the standalone-dev validator's known
//! pubkey → wallet address mapping.

use blake2::{
    digest::{consts::U32, Digest},
    Blake2b,
};
use thiserror::Error;
use tiny_keccak::{Hasher, Keccak};

use crate::base58;

/// COIN_ID bytes (`"000000"` hex).
const COIN_ID: [u8; 3] = [0x00, 0x00, 0x00];
/// VERSION byte.
const VERSION: u8 = 0x00;
/// Prefix = COIN_ID || VERSION (4 bytes).
const PREFIX: [u8; 4] = [COIN_ID[0], COIN_ID[1], COIN_ID[2], VERSION];
/// `key_hash` length — Keccak256 output.
const KEY_HASH_LEN: usize = 32;
/// Checksum length — first 4 bytes of Blake2b-256(payload).
const CHECKSUM_LEN: usize = 4;
/// Expected length of a decoded, well-formed REV address.
const DECODED_LEN: usize = PREFIX.len() + KEY_HASH_LEN + CHECKSUM_LEN;
/// Expected length of an uncompressed secp256k1 public key (04 || x || y).
const UNCOMPRESSED_PUBKEY_LEN: usize = 65;
/// Length of an Ethereum address, hex-encoded without the `0x` prefix.
const ETH_HEX_LEN: usize = 40;

/// A REV address — the base58 string a user sees in `wallets.txt`
/// and in a `/{revAddress}/` wallet mount directory.
///
/// Internally we hold the decoded bytes so `to_base58` is cheap and
/// equality is unambiguous. The base58 string form is reconstructed
/// on demand; two addresses that decode to the same bytes are equal.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct RevAddress {
    /// The 36-byte payload — prefix (4) || key_hash (32).
    payload: [u8; 36],
    /// The 4-byte checksum.
    checksum: [u8; 4],
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AddressError {
    #[error(
        "public key must be {UNCOMPRESSED_PUBKEY_LEN} bytes (uncompressed secp256k1); got {0}"
    )]
    BadKeyLength(usize),
    #[error("hex string must be {ETH_HEX_LEN} chars (optionally prefixed with 0x); got {0}")]
    BadEthHexLength(usize),
    #[error("hex decode failed: {0}")]
    BadEthHex(String),
    #[error("invalid base58 encoding: {0}")]
    BadBase58(String),
    #[error("decoded length is {0}, expected {DECODED_LEN}")]
    BadDecodedLength(usize),
    #[error("checksum mismatch")]
    BadChecksum,
    #[error("prefix mismatch")]
    BadPrefix,
}

impl RevAddress {
    /// Derive a REV address from an **uncompressed** secp256k1 public
    /// key (65 bytes beginning with `0x04`). The compressed form is
    /// not accepted — f1r3node-rust's own derivation path only takes
    /// the uncompressed form, and silently accepting both would risk
    /// producing a different address than the node for the same key.
    pub fn from_public_key_bytes(pk: &[u8]) -> Result<Self, AddressError> {
        if pk.len() != UNCOMPRESSED_PUBKEY_LEN {
            return Err(AddressError::BadKeyLength(pk.len()));
        }
        // Drop the leading 0x04 tag; hash the raw (x || y).
        let eth_hash = keccak256(&pk[1..]);
        let eth_address_hex = hex::encode(&eth_hash[eth_hash.len() - 20..]);
        Self::from_eth_address(&eth_address_hex)
    }

    /// Derive from an Ethereum address (40 hex chars, optionally
    /// `0x`-prefixed). This is the shared entry point for both the
    /// pubkey-derived and ETH-derived paths — matches
    /// `AddressTools::fromEthAddress` on dev.
    pub fn from_eth_address(eth: &str) -> Result<Self, AddressError> {
        let hex_body = eth.strip_prefix("0x").unwrap_or(eth);
        if hex_body.len() != ETH_HEX_LEN {
            return Err(AddressError::BadEthHexLength(hex_body.len()));
        }
        let eth_bytes =
            hex::decode(hex_body).map_err(|e| AddressError::BadEthHex(e.to_string()))?;
        let key_hash = keccak256(&eth_bytes);

        let mut payload = [0u8; 36];
        payload[..PREFIX.len()].copy_from_slice(&PREFIX);
        payload[PREFIX.len()..].copy_from_slice(&key_hash);

        let checksum = compute_checksum(&payload);
        Ok(Self { payload, checksum })
    }

    /// Parse a base58 REV-address string. Verifies length, prefix,
    /// and checksum; returns an error otherwise.
    pub fn parse(address: &str) -> Result<Self, AddressError> {
        let decoded = base58::decode(address).map_err(AddressError::BadBase58)?;
        if decoded.len() != DECODED_LEN {
            return Err(AddressError::BadDecodedLength(decoded.len()));
        }
        let (payload_bytes, checksum_bytes) = decoded.split_at(PREFIX.len() + KEY_HASH_LEN);
        let (actual_prefix, _) = payload_bytes.split_at(PREFIX.len());
        if actual_prefix != PREFIX {
            return Err(AddressError::BadPrefix);
        }
        let expected_checksum = compute_checksum(payload_bytes);
        if expected_checksum != checksum_bytes {
            return Err(AddressError::BadChecksum);
        }

        let mut payload = [0u8; 36];
        payload.copy_from_slice(payload_bytes);
        let mut checksum = [0u8; 4];
        checksum.copy_from_slice(checksum_bytes);
        Ok(Self { payload, checksum })
    }

    /// Serialise back to the canonical base58 form.
    pub fn to_base58(&self) -> String {
        let mut all = [0u8; DECODED_LEN];
        all[..self.payload.len()].copy_from_slice(&self.payload);
        all[self.payload.len()..].copy_from_slice(&self.checksum);
        base58::encode(&all)
    }

    /// `true` iff the given string parses as a valid REV address.
    pub fn is_valid(s: &str) -> bool {
        Self::parse(s).is_ok()
    }
}

impl std::fmt::Display for RevAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_base58())
    }
}

fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut out = [0u8; 32];
    hasher.update(input);
    hasher.finalize(&mut out);
    out
}

fn compute_checksum(payload: &[u8]) -> [u8; CHECKSUM_LEN] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(payload);
    let full = hasher.finalize();
    let mut out = [0u8; CHECKSUM_LEN];
    out.copy_from_slice(&full[..CHECKSUM_LEN]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Standalone-dev genesis validator — pubkey from
    /// `f1r3node-rust/docker/genesis/standalone-bonds.txt`, REV
    /// address from `standalone-wallets.txt`. If this test fails,
    /// the derivation algorithm has drifted from the chain's.
    const VALIDATOR_PUBKEY_HEX: &str = "04ffc016579a68050d655d55df4e09f04605164543e257c8e6df10361e6068a5336588e9b355ea859c5ab4285a5ef0efdf62bc28b80320ce99e26bb1607b3ad93d";
    const VALIDATOR_REV_ADDRESS: &str = "1111AtahZeefej4tvVR6ti9TJtv8yxLebT31SCEVDCKMNikBk5r3g";

    #[test]
    fn derive_validator_rev_address_matches_wallets_txt() {
        let pk = hex::decode(VALIDATOR_PUBKEY_HEX).unwrap();
        let addr = RevAddress::from_public_key_bytes(&pk).unwrap();
        assert_eq!(addr.to_base58(), VALIDATOR_REV_ADDRESS);
    }

    #[test]
    fn parse_round_trips_validator_address() {
        let addr = RevAddress::parse(VALIDATOR_REV_ADDRESS).unwrap();
        assert_eq!(addr.to_base58(), VALIDATOR_REV_ADDRESS);
    }

    #[test]
    fn parse_and_derive_agree() {
        let pk = hex::decode(VALIDATOR_PUBKEY_HEX).unwrap();
        let derived = RevAddress::from_public_key_bytes(&pk).unwrap();
        let parsed = RevAddress::parse(VALIDATOR_REV_ADDRESS).unwrap();
        assert_eq!(derived, parsed);
    }

    #[test]
    fn eth_hex_accepts_both_prefixed_and_bare() {
        let pk = hex::decode(VALIDATOR_PUBKEY_HEX).unwrap();
        // Reproduce the ETH address the derivation uses internally.
        let eth_hash = keccak256(&pk[1..]);
        let eth_hex = hex::encode(&eth_hash[eth_hash.len() - 20..]);

        let a = RevAddress::from_eth_address(&eth_hex).unwrap();
        let b = RevAddress::from_eth_address(&format!("0x{eth_hex}")).unwrap();
        let via_pk = RevAddress::from_public_key_bytes(&pk).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, via_pk);
    }

    #[test]
    fn rejects_bad_key_length() {
        assert_eq!(
            RevAddress::from_public_key_bytes(&[0u8; 64]),
            Err(AddressError::BadKeyLength(64)),
        );
    }

    #[test]
    fn rejects_bad_checksum() {
        // Flip the last byte — checksum fails.
        let mut s = VALIDATOR_REV_ADDRESS.chars().collect::<Vec<_>>();
        let last = s.last_mut().unwrap();
        *last = if *last == '1' { '2' } else { '1' };
        let corrupted: String = s.into_iter().collect();
        assert!(matches!(
            RevAddress::parse(&corrupted),
            Err(AddressError::BadChecksum) | Err(AddressError::BadDecodedLength(_)),
        ));
    }

    #[test]
    fn rejects_invalid_base58() {
        assert!(matches!(
            RevAddress::parse("not-base58-0OIl"),
            Err(AddressError::BadBase58(_)),
        ));
    }

    #[test]
    fn is_valid_matches_parse() {
        assert!(RevAddress::is_valid(VALIDATOR_REV_ADDRESS));
        assert!(!RevAddress::is_valid("not an address"));
    }

    #[test]
    fn display_equals_to_base58() {
        let addr = RevAddress::parse(VALIDATOR_REV_ADDRESS).unwrap();
        assert_eq!(format!("{addr}"), addr.to_base58());
    }
}
