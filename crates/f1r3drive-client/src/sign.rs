//! DeployDataProto signing.
//!
//! The protocol-v6 (2026-09+) encoding is implemented in [`DeployToSign::sign`],
//! matching `f1r3node-rust/crypto/src/rust/signatures/signed.rs`
//! (`Cosigned::envelope_commitment_for_canonical`, `..._signature_hash_for_commitment`)
//! and the server-side `DeployData::from_proto_cosigned` validation at
//! `casper/protocol/casper_message.rs:2763`.
//!
//! Flow (single-signer secp256k1):
//!
//!   1. Build the deploy intent — a canonical length-prefixed byte string
//!      covering term + timestamp + valid-after + shard_id + expiration +
//!      authority_presentations. Matches `DeployData::envelope_intent_v61`.
//!   2. Build the policy bytes — tag byte + threshold/signer counts +
//!      each principal (`scheme_id ∥ pk_len ∥ pk_bytes`). For one signer
//!      with threshold=1, tag=1 (AllOf) + `be_u32(1)` + principal.
//!   3. Build the commitment preimage: domain string, protocol version
//!      (`6`), intent, policy, bitmap. Blake2b256 → 32-byte `deploy_id`.
//!   4. Build the signature message: signature-domain string, version,
//!      scheme id, commitment. Blake2b256 → signing hash.
//!   5. secp256k1 ECDSA prehash-sign; normalize s to low-s; DER-encode.
//!   6. Pack into `DeployDataProto` with EMPTY legacy fields and a
//!      `DeployAuthorizationV61` carrying the policy, bitmap, and
//!      witness.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::Signature;

use f1r3drive_proto::casper::{
    authorization_policy_v61::Policy as PolicyProto, AllOfPolicyV61, AuthorizationPolicyV61,
    DeployAuthorizationV61, DeployDataProto, PrincipalV61, SignatureSchemeV61, SignatureWitnessV61,
};

use crate::error::ClientError;
use crate::key::KeyPair;

/// `blake2b` with a 32-byte output — the hash f1r3node-rust uses for both
/// the envelope commitment and the per-scheme signing hash.
type Blake2b256 = Blake2b<U32>;

/// Domain-separation tag for the envelope commitment preimage.
/// Must byte-match `ENVELOPE_COMMITMENT_DOMAIN` in
/// `crypto/src/rust/signatures/signed.rs:79`.
const ENVELOPE_COMMITMENT_DOMAIN: &[u8] = b"f1r3fly:casper:deploy-envelope:v6.1";

/// Domain-separation tag for the per-signer signing-hash preimage.
const ENVELOPE_SIGNATURE_DOMAIN: &[u8] = b"f1r3fly:casper:deploy-envelope-signature:v6.1";

/// Protocol version baked into the commitment + signature preimages.
const ENVELOPE_PROTOCOL_VERSION: u16 = 6;

/// `format_version` the server requires on
/// `DeployAuthorizationV61.format_version`. See
/// `casper/protocol/casper_message.rs:2788`.
const V61_FORMAT_VERSION: u32 = 0x0006_0001;

/// `scheme` id for secp256k1 (matches `SignatureSchemeV61::Secp256k1 = 1`
/// in the proto enum and `envelope_scheme_id("secp256k1") == 1` in the
/// crypto crate).
const SCHEME_SECP256K1: u16 = 1;

/// Length-prefix a byte slice with `be_u64` as the server's
/// `append_commitment_field` / `append_deploy_intent_field` do.
fn append_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Serialize one envelope `principal` (signer scheme + pk) as the crypto
/// crate's `principal_bytes` does:
///   `be_u16(scheme) ∥ be_u32(pk_len) ∥ pk`.
fn principal_bytes(scheme_id: u16, pk: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 4 + pk.len());
    out.extend_from_slice(&scheme_id.to_be_bytes());
    out.extend_from_slice(&(pk.len() as u32).to_be_bytes());
    out.extend_from_slice(pk);
    out
}

/// Builder-style helper that holds the raw fields of a user deploy and
/// knows how to sign them into a v6 `DeployDataProto`.
#[derive(Debug, Clone)]
pub struct DeployToSign {
    pub term: String,
    pub shard_id: String,
    pub timestamp_millis: i64,
    pub valid_after_block_number: i64,
    /// `None` → omitted on the wire (encodes as a single `0` byte in the
    /// intent). The server rejects negative or zero `Some(_)` values.
    pub expiration_timestamp: Option<i64>,
    /// Carried in the proto but discarded by `_to_proto`; see Rust docs
    /// on `DeployData._to_proto` for the "language is stripped at hash
    /// time" quirk. v6 requires it be `"rholang"` at intent-build time.
    pub language: String,
}

impl DeployToSign {
    /// Default fields matching what a FUSE write would set:
    /// current wall-clock timestamp, no block floor, no expiration,
    /// language `"rholang"`.
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

    /// Build the v6 `envelope intent` byte string — the canonical
    /// identity-bearing portion of the deploy that the commitment folds
    /// over. Must byte-match `DeployData::envelope_intent_v61` on the
    /// server (`casper/protocol/casper_message.rs:2412`).
    fn envelope_intent(&self) -> Result<Vec<u8>, ClientError> {
        if self.language != "rholang" {
            return Err(ClientError::Sign(
                "protocol-v6 deploy language must be rholang".into(),
            ));
        }
        let timestamp = u64::try_from(self.timestamp_millis)
            .map_err(|_| ClientError::Sign("timestamp must be nonnegative".into()))?;
        let valid_after = u64::try_from(self.valid_after_block_number)
            .map_err(|_| ClientError::Sign("valid-after block must be nonnegative".into()))?;
        if self.shard_id.is_empty() {
            return Err(ClientError::Sign("shard ID must be nonempty".into()));
        }

        let mut intent = Vec::new();
        intent.extend_from_slice(&1u16.to_be_bytes());
        intent.push(1);
        append_field(&mut intent, self.term.as_bytes());
        intent.extend_from_slice(&timestamp.to_be_bytes());
        intent.extend_from_slice(&valid_after.to_be_bytes());
        append_field(&mut intent, self.shard_id.as_bytes());
        match self.expiration_timestamp {
            None => intent.push(0),
            Some(exp) if exp > 0 => {
                intent.push(1);
                intent.extend_from_slice(&(exp as u64).to_be_bytes());
            }
            Some(_) => {
                return Err(ClientError::Sign(
                    "expiration_timestamp must be positive".into(),
                ));
            }
        }
        // authority_presentations: not supported in this client yet,
        // encoded as `be_u32(0)` (empty list).
        intent.extend_from_slice(&0u32.to_be_bytes());
        Ok(intent)
    }

    /// Sign and produce a v6 wire `DeployDataProto`. Returns a proto
    /// whose legacy fields (`deployer`, `sig`, `sig_algorithm`,
    /// `cosigners`, `cosigner_threshold`, `sig_algebra`) are empty and
    /// whose `deploy_id` + `authorization_v61` carry the envelope.
    pub fn sign(&self, key: &KeyPair) -> Result<DeployDataProto, ClientError> {
        let pk = key.public_key_bytes().to_vec();
        let intent = self.envelope_intent()?;

        // Policy: single-signer AllOf. tag=1, total_signers=1, then one
        // principal.
        let mut policy = Vec::new();
        policy.push(1u8);
        policy.extend_from_slice(&1u32.to_be_bytes()); // total_signers = 1
        policy.extend_from_slice(&principal_bytes(SCHEME_SECP256K1, &pk));

        // Presence bitmap: one byte, bit 0 set (our single signer provides a sig).
        let bitmap = vec![0x01u8];

        // Commitment preimage.
        let mut preimage = Vec::new();
        append_field(&mut preimage, ENVELOPE_COMMITMENT_DOMAIN);
        preimage.extend_from_slice(&ENVELOPE_PROTOCOL_VERSION.to_be_bytes());
        append_field(&mut preimage, &intent);
        append_field(&mut preimage, &policy);
        preimage.extend_from_slice(&(bitmap.len() as u32).to_be_bytes());
        preimage.extend_from_slice(&bitmap);

        let commitment: [u8; 32] = {
            let mut h = Blake2b256::new();
            h.update(&preimage);
            h.finalize().into()
        };

        // Signature preimage.
        let mut sig_msg = Vec::new();
        append_field(&mut sig_msg, ENVELOPE_SIGNATURE_DOMAIN);
        sig_msg.extend_from_slice(&ENVELOPE_PROTOCOL_VERSION.to_be_bytes());
        sig_msg.extend_from_slice(&SCHEME_SECP256K1.to_be_bytes());
        sig_msg.extend_from_slice(&commitment);
        let signing_hash: [u8; 32] = {
            let mut h = Blake2b256::new();
            h.update(&sig_msg);
            h.finalize().into()
        };

        // Sign and normalize to low-s (server's `canonical_envelope_signature`
        // requires `normalize_s().is_none()` on the submitted signature,
        // i.e. the sig must already be in low-s form).
        let raw_sig: Signature = key
            .signing_key
            .sign_prehash(&signing_hash)
            .map_err(|e| ClientError::Sign(format!("prehash sign failed: {e}")))?;
        let normalized = raw_sig.normalize_s().unwrap_or(raw_sig);
        let der = normalized.to_der().as_bytes().to_vec();

        // Build the v6 proto.
        let auth = DeployAuthorizationV61 {
            format_version: V61_FORMAT_VERSION,
            policy: Some(AuthorizationPolicyV61 {
                policy: Some(PolicyProto::AllOf(AllOfPolicyV61 {
                    members: vec![PrincipalV61 {
                        scheme: SignatureSchemeV61::Secp256k1 as i32,
                        public_key: bytes::Bytes::from(pk),
                    }],
                })),
            }),
            presence_bitmap: bytes::Bytes::from(bitmap),
            witnesses: vec![SignatureWitnessV61 {
                member_index: 0,
                signature: bytes::Bytes::from(der),
            }],
        };

        Ok(DeployDataProto {
            // Legacy fields must be empty on a v6 submission.
            deployer: bytes::Bytes::new(),
            sig: bytes::Bytes::new(),
            sig_algorithm: String::new(),
            cosigners: Vec::new(),
            cosigner_threshold: 0,
            sig_algebra: None,
            // Data fields carry the user payload.
            term: self.term.clone(),
            timestamp: self.timestamp_millis,
            valid_after_block_number: self.valid_after_block_number,
            shard_id: self.shard_id.clone(),
            language: self.language.clone(),
            expiration_timestamp: self.expiration_timestamp.unwrap_or(0),
            authority_presentations: Vec::new(),
            // v6 envelope.
            deploy_id: bytes::Bytes::copy_from_slice(&commitment),
            authorization_v61: Some(auth),
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
    fn sign_produces_32_byte_deploy_id_and_v6_fields() {
        let key = KeyPair::from_private_hex(KNOWN_SK_HEX).unwrap();
        let unsigned = DeployToSign::new_now("Nil", "root");
        let signed = unsigned.sign(&key).expect("sign");

        // Legacy fields must be empty.
        assert!(signed.deployer.is_empty());
        assert!(signed.sig.is_empty());
        assert!(signed.sig_algorithm.is_empty());
        assert_eq!(signed.cosigner_threshold, 0);
        assert!(signed.cosigners.is_empty());
        assert!(signed.sig_algebra.is_none());

        // v6 envelope present.
        assert_eq!(signed.deploy_id.len(), 32);
        let auth = signed.authorization_v61.as_ref().expect("auth");
        assert_eq!(auth.format_version, V61_FORMAT_VERSION);
        assert_eq!(auth.presence_bitmap.as_ref(), &[0x01u8]);
        assert_eq!(auth.witnesses.len(), 1);
        assert_eq!(auth.witnesses[0].member_index, 0);
        assert!(!auth.witnesses[0].signature.is_empty());

        // Policy is single-member AllOf with our pk.
        let policy = auth
            .policy
            .as_ref()
            .and_then(|p| p.policy.as_ref())
            .expect("policy present");
        match policy {
            PolicyProto::AllOf(all) => {
                assert_eq!(all.members.len(), 1);
                assert_eq!(all.members[0].scheme, SignatureSchemeV61::Secp256k1 as i32);
                assert_eq!(all.members[0].public_key.as_ref(), key.public_key_bytes());
            }
            _ => panic!("expected AllOf policy"),
        }
    }

    /// Mirror the server's commitment+signature preimage reconstruction
    /// and verify the submitted signature with the embedded pk. If this
    /// test passes, `DeployData::from_proto_cosigned` will accept the
    /// signature at the signature-verification step.
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
        };
        let signed = unsigned.sign(&key).unwrap();

        // Rebuild intent + policy + bitmap from the deploy data the way
        // the server will after decoding the proto.
        let intent = unsigned.envelope_intent().unwrap();
        let pk = key.public_key_bytes().to_vec();
        let mut policy = Vec::new();
        policy.push(1u8);
        policy.extend_from_slice(&1u32.to_be_bytes());
        policy.extend_from_slice(&principal_bytes(SCHEME_SECP256K1, &pk));
        let bitmap: Vec<u8> = signed
            .authorization_v61
            .as_ref()
            .unwrap()
            .presence_bitmap
            .to_vec();

        let mut preimage = Vec::new();
        append_field(&mut preimage, ENVELOPE_COMMITMENT_DOMAIN);
        preimage.extend_from_slice(&ENVELOPE_PROTOCOL_VERSION.to_be_bytes());
        append_field(&mut preimage, &intent);
        append_field(&mut preimage, &policy);
        preimage.extend_from_slice(&(bitmap.len() as u32).to_be_bytes());
        preimage.extend_from_slice(&bitmap);
        let commitment: [u8; 32] = {
            let mut h = Blake2b256::new();
            h.update(&preimage);
            h.finalize().into()
        };
        assert_eq!(signed.deploy_id.as_ref(), commitment.as_slice());

        let mut sig_msg = Vec::new();
        append_field(&mut sig_msg, ENVELOPE_SIGNATURE_DOMAIN);
        sig_msg.extend_from_slice(&ENVELOPE_PROTOCOL_VERSION.to_be_bytes());
        sig_msg.extend_from_slice(&SCHEME_SECP256K1.to_be_bytes());
        sig_msg.extend_from_slice(&commitment);
        let signing_hash: [u8; 32] = {
            let mut h = Blake2b256::new();
            h.update(&sig_msg);
            h.finalize().into()
        };

        let witness = &signed.authorization_v61.as_ref().unwrap().witnesses[0];
        let encoded = EncodedPoint::from_bytes(key.public_key_bytes()).unwrap();
        let vk = VerifyingKey::from(k256::PublicKey::from_encoded_point(&encoded).unwrap());
        let sig = Signature::from_der(&witness.signature).unwrap();
        // Server also checks `normalize_s().is_none()` — i.e. that the sig
        // we emitted is already in low-s canonical form.
        assert!(sig.normalize_s().is_none(), "signature must be low-s");
        vk.verify_prehash(&signing_hash, &sig)
            .expect("signature must verify");
    }
}
