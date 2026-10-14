//! DeployDataProto signing matching f1r3node-rust's `DeployData::from_proto`
//! round trip.
//!
//! For a legacy single-signer deploy with `sig_algorithm = "secp256k1"`, the
//! node reconstructs the preimage by stripping `deployer`, `sig`,
//! `sig_algorithm`, `cosigners`, `cosigner_threshold`, `deploy_id`,
//! `authorization_v61`, and `sig_algebra` from the proto, re-encoding, then
//! Blake2b256-hashing the serialized bytes and verifying the DER signature
//! against the embedded `deployer` public key.
//!
//! See `f1r3node-rust/crypto/src/rust/signatures/signed.rs:794` (`Signed::create`)
//! and `casper/protocol/casper_message.rs:3037` (`_to_proto`).

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::Signature;
use prost::Message;

use f1r3drive_proto::casper::DeployDataProto;

use crate::error::ClientError;
use crate::key::KeyPair;

/// `blake2b` with a 32-byte output — the hash f1r3node-rust uses for
/// `sig_algorithm = "secp256k1"` (see `Signed::signature_hash`).
type Blake2b256 = Blake2b<U32>;

/// Builder-style helper that constructs the pre-signature preimage for a
/// deploy, exactly matching what f1r3node-rust will re-derive on receipt.
#[derive(Debug, Clone)]
pub struct DeployToSign {
    pub term: String,
    pub shard_id: String,
    pub timestamp_millis: i64,
    pub valid_after_block_number: i64,
    /// `None` → `0` on the wire (no expiration).
    pub expiration_timestamp: Option<i64>,
    pub language: String,
}

impl DeployToSign {
    /// A convenience constructor matching the fields the Java f1r3drive
    /// typically fills in: current wall-clock time, no block floor, no
    /// expiration, `language = "rholang"`.
    pub fn new_now(term: impl Into<String>, shard_id: impl Into<String>) -> Self {
        let timestamp_millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        Self {
            term: term.into(),
            shard_id: shard_id.into(),
            timestamp_millis,
            valid_after_block_number: 0,
            expiration_timestamp: None,
            language: "rholang".to_string(),
        }
    }

    /// Produce the preimage proto with the fields the server expects to be
    /// present at hash time. Mirrors `DeployData::_to_proto`.
    fn preimage_proto(&self) -> DeployDataProto {
        DeployDataProto {
            term: self.term.clone(),
            // _to_proto writes language = String::new(), discarding the client's
            // language field. We match that so hashes line up on both sides.
            language: String::new(),
            timestamp: self.timestamp_millis,
            valid_after_block_number: self.valid_after_block_number,
            shard_id: self.shard_id.clone(),
            expiration_timestamp: self.expiration_timestamp.unwrap_or(0),
            ..DeployDataProto::default()
        }
    }

    /// Sign and produce the full wire proto to send to `doDeploy`.
    pub fn sign(&self, key: &KeyPair) -> Result<DeployDataProto, ClientError> {
        let preimage = self.preimage_proto();
        let preimage_bytes = preimage.encode_to_vec();

        let mut hasher = Blake2b256::new();
        hasher.update(&preimage_bytes);
        let hash = hasher.finalize();

        let signature: Signature = key
            .signing_key
            .sign_prehash(&hash)
            .map_err(|e| ClientError::Sign(format!("prehash sign failed: {e}")))?;
        let der = signature.to_der().as_bytes().to_vec();

        Ok(DeployDataProto {
            deployer: bytes::Bytes::from(key.public_key_bytes.clone()),
            term: self.term.clone(),
            timestamp: self.timestamp_millis,
            sig: bytes::Bytes::from(der),
            sig_algorithm: "secp256k1".to_string(),
            valid_after_block_number: self.valid_after_block_number,
            shard_id: self.shard_id.clone(),
            // _to_proto strips language, but the client-visible proto still
            // carries it back out — follow the server's to_proto_ref shape.
            language: self.language.clone(),
            expiration_timestamp: self.expiration_timestamp.unwrap_or(0),
            ..DeployDataProto::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::hazmat::PrehashVerifier;
    use k256::ecdsa::VerifyingKey;
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::EncodedPoint;

    const KNOWN_SK_HEX: &str = "4f8f5e4a6c7b1c7e3a9d8f2e1b0c5a4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b";

    #[test]
    fn sign_matches_server_side_reconstruction() {
        let key = KeyPair::from_private_hex(KNOWN_SK_HEX).unwrap();
        let unsigned = DeployToSign {
            term: "Nil".to_string(),
            shard_id: "root".to_string(),
            timestamp_millis: 1_700_000_000_000,
            valid_after_block_number: 0,
            expiration_timestamp: None,
            language: "rholang".to_string(),
        };
        let signed = unsigned.sign(&key).unwrap();

        // Server reconstructs the preimage by stripping deployer/sig/sig_algorithm
        // from the received proto and re-encoding. Verify that if we do the
        // same strip + hash + verify roundtrip, the signature validates.
        let stripped = DeployDataProto {
            deployer: Default::default(),
            sig: Default::default(),
            sig_algorithm: String::new(),
            language: String::new(),
            ..signed.clone()
        };
        let preimage_bytes = stripped.encode_to_vec();
        let mut hasher = Blake2b256::new();
        hasher.update(&preimage_bytes);
        let hash = hasher.finalize();

        let encoded = EncodedPoint::from_bytes(&signed.deployer).unwrap();
        let vk = VerifyingKey::from(k256::PublicKey::from_encoded_point(&encoded).unwrap());
        let sig = Signature::from_der(&signed.sig).unwrap();
        vk.verify_prehash(&hash, &sig)
            .expect("signature must verify");
    }
}
