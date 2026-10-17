//! Legacy single-signer `DeployDataProto` signing.
//!
//! This matches f1r3node-rust **dev** semantics:
//! `casper/protocol/casper_message.rs::DeployData::from_proto` resolves a
//! named signature algorithm from `sig_algorithm`, re-encodes the deploy
//! data via `_to_proto` (which drops `deployer`, `sig`, `sig_algorithm`,
//! `language`), hashes with Blake2b256 (via
//! `Signed::signature_hash` default arm), and verifies ECDSA-DER with
//! the embedded `deployer` pubkey.
//!
//! Protocol-v6 cosigned envelopes (`authorization_v61`, `cosigners`,
//! `cosigner_threshold`) are a *fileio-branch* feature line that hasn't
//! landed on dev. If / when it does, add a dual-mode `sign_v6` here and
//! let the daemon pick via `--protocol-version` or server-probe.
//!
//! Flow:
//!   1. Build a bare `DeployDataProto` carrying only the fields
//!      `_to_proto` preserves: `term`, `timestamp`, `phlo_price`,
//!      `phlo_limit`, `valid_after_block_number`, `shard_id`,
//!      `expiration_timestamp`, `parameters`.
//!   2. Serialize that bare proto with prost → preimage.
//!   3. `Blake2b256(preimage)` → 32-byte signing hash.
//!   4. secp256k1 ECDSA prehash-sign; DER-encode.
//!   5. Return a fully-populated `DeployDataProto` with `deployer`
//!      (65-byte uncompressed SEC1 pubkey), `sig` (DER), and
//!      `sig_algorithm = "secp256k1"` filled.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::Signature;
use prost::Message;

use f1r3drive_proto::casper::DeployDataProto;

use crate::error::ClientError;
use crate::key::KeyPair;

/// `blake2b` with a 32-byte output — the hash f1r3node-rust uses in the
/// default arm of `Signed::signature_hash` for secp256k1.
type Blake2b256 = Blake2b<U32>;

/// `sig_algorithm` string the server resolves via
/// `SignaturesAlgFactory::apply`. Byte-identical to `Secp256k1::name()`
/// in `crypto/src/rust/signatures/secp256k1.rs`.
const SIG_ALGORITHM_SECP256K1: &str = "secp256k1";

/// Default phlo price for FUSE-submitted deploys. Standalone-dev shards
/// configure `min-phlo-price = 1`; the deploy's `phlo_price` has to meet
/// or exceed that at admission. Keeping it at the floor so the daemon
/// doesn't burn tokens needlessly.
const DEFAULT_PHLO_PRICE: i64 = 1;

/// Default phlo limit. Big enough to execute any Fs-agent op we emit
/// without tripping out-of-phlo mid-reduction; small enough to be a
/// cheap bound.
const DEFAULT_PHLO_LIMIT: i64 = 10_000_000;

/// Builder-style helper that holds the raw fields of a user deploy and
/// knows how to sign them into a legacy single-sig `DeployDataProto`.
#[derive(Debug, Clone)]
pub struct DeployToSign {
    pub term: String,
    pub shard_id: String,
    pub timestamp_millis: i64,
    pub valid_after_block_number: i64,
    /// `None` → encoded as `0` on the wire ("no expiration").
    pub expiration_timestamp: Option<i64>,
    /// Carried in the proto but discarded by `_to_proto`, so it doesn't
    /// participate in the signing hash. Server reads it off the wire
    /// for its own routing / parser dispatch.
    pub language: String,
    /// Per-COMM phlo price. Must meet shard `min-phlo-price` at admission.
    pub phlo_price: i64,
    /// Per-deploy phlo limit.
    pub phlo_limit: i64,
}

impl DeployToSign {
    /// Default fields matching what a FUSE write would set.
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
            phlo_price: DEFAULT_PHLO_PRICE,
            phlo_limit: DEFAULT_PHLO_LIMIT,
        }
    }

    /// Build the server-visible "signing proto" — i.e. the exact proto
    /// shape `DeployData::_to_proto` produces, which has only the
    /// deploy's data fields and leaves every other `DeployDataProto`
    /// slot at its proto default. The signing hash covers exactly this
    /// preimage.
    fn signing_proto(&self) -> DeployDataProto {
        DeployDataProto {
            term: self.term.clone(),
            timestamp: self.timestamp_millis,
            phlo_price: self.phlo_price,
            phlo_limit: self.phlo_limit,
            valid_after_block_number: self.valid_after_block_number,
            shard_id: self.shard_id.clone(),
            expiration_timestamp: self.expiration_timestamp.unwrap_or(0),
            parameters: Vec::new(),
            ..Default::default()
        }
    }

    /// Sign and produce a wire-ready `DeployDataProto` with
    /// `deployer`, `sig`, and `sig_algorithm` populated.
    pub fn sign(&self, key: &KeyPair) -> Result<DeployDataProto, ClientError> {
        if self.shard_id.is_empty() {
            return Err(ClientError::Sign("shard ID must be nonempty".into()));
        }

        let signing_proto = self.signing_proto();
        let preimage = signing_proto.encode_to_vec();

        let hash: [u8; 32] = {
            let mut h = Blake2b256::new();
            h.update(&preimage);
            h.finalize().into()
        };

        let sig: Signature = key
            .signing_key
            .sign_prehash(&hash)
            .map_err(|e| ClientError::Sign(format!("prehash sign failed: {e}")))?;
        let der = sig.to_der().as_bytes().to_vec();

        Ok(DeployDataProto {
            deployer: bytes::Bytes::copy_from_slice(key.public_key_bytes()),
            sig: bytes::Bytes::from(der),
            sig_algorithm: SIG_ALGORITHM_SECP256K1.to_string(),
            // Data fields echoing `signing_proto`.
            term: self.term.clone(),
            timestamp: self.timestamp_millis,
            phlo_price: self.phlo_price,
            phlo_limit: self.phlo_limit,
            valid_after_block_number: self.valid_after_block_number,
            shard_id: self.shard_id.clone(),
            language: self.language.clone(),
            expiration_timestamp: self.expiration_timestamp.unwrap_or(0),
            parameters: Vec::new(),
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
    fn sign_populates_deployer_sig_sigalgorithm() {
        let key = KeyPair::from_private_hex(KNOWN_SK_HEX).unwrap();
        let unsigned = DeployToSign::new_now("Nil", "root");
        let signed = unsigned.sign(&key).expect("sign");

        assert_eq!(signed.deployer.len(), 65);
        assert_eq!(signed.deployer.as_ref(), key.public_key_bytes());
        assert_eq!(signed.sig_algorithm, "secp256k1");
        assert!(!signed.sig.is_empty());
        // DeployData payload survives.
        assert_eq!(signed.term, "Nil");
        assert_eq!(signed.shard_id, "root");
        assert_eq!(signed.phlo_price, DEFAULT_PHLO_PRICE);
        assert_eq!(signed.phlo_limit, DEFAULT_PHLO_LIMIT);
    }

    /// Mirror the server's `DeployData::from_proto` reconstruction:
    /// decode payload, strip `deployer` / `sig` / `sig_algorithm` /
    /// `language` via `_to_proto`, hash with Blake2b256, verify ECDSA
    /// against the embedded pubkey. If this passes, dev's
    /// `Signed::from_signed_data` accepts the signature.
    #[test]
    fn signature_verifies_against_server_reconstructed_hash() {
        let key = KeyPair::from_private_hex(KNOWN_SK_HEX).unwrap();
        let unsigned = DeployToSign {
            term: "Nil".to_string(),
            shard_id: "root".to_string(),
            timestamp_millis: 1_700_000_000_000,
            valid_after_block_number: 0,
            expiration_timestamp: None,
            language: "rholang".to_string(),
            phlo_price: 1,
            phlo_limit: 10_000_000,
        };
        let signed = unsigned.sign(&key).unwrap();

        // Rebuild the signing-proto preimage the way the server does:
        // extract the data fields, drop deployer/sig/sig_algorithm/language,
        // re-encode.
        let server_side_signing_proto = DeployDataProto {
            term: signed.term.clone(),
            timestamp: signed.timestamp,
            phlo_price: signed.phlo_price,
            phlo_limit: signed.phlo_limit,
            valid_after_block_number: signed.valid_after_block_number,
            shard_id: signed.shard_id.clone(),
            expiration_timestamp: signed.expiration_timestamp,
            parameters: signed.parameters.clone(),
            ..Default::default()
        };
        let preimage = server_side_signing_proto.encode_to_vec();
        let hash: [u8; 32] = {
            let mut h = Blake2b256::new();
            h.update(&preimage);
            h.finalize().into()
        };

        let encoded = EncodedPoint::from_bytes(key.public_key_bytes()).unwrap();
        let vk = VerifyingKey::from(k256::PublicKey::from_encoded_point(&encoded).unwrap());
        let sig = Signature::from_der(&signed.sig).unwrap();
        vk.verify_prehash(&hash, &sig)
            .expect("signature must verify against Blake2b256 of the signing proto");
    }
}
