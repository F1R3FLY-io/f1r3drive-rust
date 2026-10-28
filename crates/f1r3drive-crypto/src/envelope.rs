//! SELF and RECV envelope formats.
//!
//! Both envelopes carry a plaintext filename and plaintext length
//! encrypted inside the AES-GCM payload. The on-chain blob leaks
//! only: tag (4 B), fingerprint-or-ECIES-wrapper, GCM nonce/tag,
//! and padded ciphertext length.
//!
//! Wire format:
//!
//! ```text
//! SELF:  "SELF" || blake2b256(K) || AES-GCM(K, hdr || padded_plaintext)
//! RECV:  "RECV" || ECIES(pk, K)  || AES-GCM(K, hdr || padded_plaintext)
//!
//! hdr =  <u64 LE true_length> || <u16 LE filename_len> || filename_bytes
//! padded_plaintext = plaintext || zero-pad to next bucket boundary
//! ```
//!
//! The AES-GCM output embeds its own 12-byte nonce + 16-byte tag per
//! [`crate::sym`]. Padding bucket boundaries come from
//! [`bucket_size`]; see ADR-0002 §Decisions.

use crate::asym::{ecies_unwrap, ecies_wrap};
use crate::error::{CryptoError, Result};
use crate::hash::{key_fingerprint, FINGERPRINT_LEN};
use crate::sym::{generate_key, open as aes_open, seal as aes_seal, SymKey};

pub const SELF_TAG: [u8; 4] = *b"SELF";
pub const RECV_TAG: [u8; 4] = *b"RECV";
/// `SELF` with the symmetric key wrapped to the owner's own pubkey
/// via ECIES — self-contained like `RECV`, no separate keystore
/// entry. See [ADR-0003](../../../docs/architecture/ADR-0003-stateless-self-envelopes.md)
/// for the migration path.
pub const SLFW_TAG: [u8; 4] = *b"SLFW";

/// Pad an N-byte plaintext up to the smallest bucket >= N.
///
/// Buckets: 1 KiB, 4 KiB, 64 KiB, 1 MiB, 16 MiB, 256 MiB, 4 GiB.
/// Anything over 4 GiB rounds up to the next 16-MiB-aligned size
/// (we don't want a huge content item to leak its true size by
/// falling into a bucket of its own).
pub fn bucket_size(n: u64) -> u64 {
    const BUCKETS: &[u64] = &[
        1 << 10, // 1 KiB
        1 << 12, // 4 KiB
        1 << 16, // 64 KiB
        1 << 20, // 1 MiB
        1 << 24, // 16 MiB
        1 << 28, // 256 MiB
        1 << 32, // 4 GiB
    ];
    for &b in BUCKETS {
        if n <= b {
            return b;
        }
    }
    // Beyond 4 GiB: round up to next 16-MiB boundary.
    let step = 1u64 << 24;
    n.div_ceil(step) * step
}

/// Deserialised view of a successful envelope unwrap.
#[derive(Debug)]
pub struct UnwrappedBlob {
    pub filename: String,
    pub plaintext: Vec<u8>,
}

/// Header record encoded inside the AES-GCM payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeHeader {
    pub true_length: u64,
    pub filename: String,
}

impl EnvelopeHeader {
    fn encode(&self) -> Result<Vec<u8>> {
        let name = self.filename.as_bytes();
        if name.contains(&0u8) {
            return Err(CryptoError::NulInFilename);
        }
        let name_len: u16 = name
            .len()
            .try_into()
            .map_err(|_| CryptoError::HeaderParse("filename > 65535 bytes".into()))?;
        let mut out = Vec::with_capacity(8 + 2 + name.len());
        out.extend_from_slice(&self.true_length.to_le_bytes());
        out.extend_from_slice(&name_len.to_le_bytes());
        out.extend_from_slice(name);
        Ok(out)
    }

    fn decode(buf: &[u8]) -> Result<(Self, &[u8])> {
        if buf.len() < 10 {
            return Err(CryptoError::HeaderParse(format!(
                "header < 10 bytes ({})",
                buf.len()
            )));
        }
        let true_length = u64::from_le_bytes(buf[..8].try_into().unwrap());
        let name_len = u16::from_le_bytes(buf[8..10].try_into().unwrap()) as usize;
        let body_start = 10 + name_len;
        if buf.len() < body_start {
            return Err(CryptoError::HeaderParse(format!(
                "name_len {} exceeds buffer ({})",
                name_len,
                buf.len() - 10
            )));
        }
        let filename = std::str::from_utf8(&buf[10..body_start])
            .map_err(|e| CryptoError::HeaderParse(format!("non-utf8 filename: {e}")))?
            .to_string();
        Ok((
            Self {
                true_length,
                filename,
            },
            &buf[body_start..],
        ))
    }
}

/// Opaque envelope — type tag + wrapper bytes + sealed body. The
/// mount layer passes the `bytes` vector into `Fs.File.writeBytesAt`
/// unchanged.
#[derive(Debug, Clone)]
pub struct Envelope {
    pub bytes: Vec<u8>,
}

/// Wrap `plaintext` as a SELF envelope under `key`. Returns the
/// envelope bytes AND the key fingerprint — the caller stores the
/// fingerprint-indexed key in the keystore. Padding goes up to the
/// bucket defined by [`bucket_size`] applied to the SIZE OF THE
/// HEADER-PLUS-PLAINTEXT so the on-chain ciphertext length lives on
/// a bucket boundary regardless of filename length.
pub fn wrap_self(
    key: &SymKey,
    filename: &str,
    plaintext: &[u8],
) -> Result<(Envelope, [u8; FINGERPRINT_LEN])> {
    let header = EnvelopeHeader {
        true_length: plaintext.len() as u64,
        filename: filename.to_string(),
    };
    let body = pad_body(&header, plaintext)?;
    let sealed = aes_seal(key, &body);
    let fp = key_fingerprint(key.as_bytes());
    let mut out = Vec::with_capacity(4 + FINGERPRINT_LEN + sealed.len());
    out.extend_from_slice(&SELF_TAG);
    out.extend_from_slice(&fp);
    out.extend_from_slice(&sealed);
    Ok((Envelope { bytes: out }, fp))
}

/// Wrap `plaintext` as a `SLFW` envelope — a self-ECIES equivalent of
/// `wrap_self` that keeps K inside the envelope instead of in a side
/// keystore. See ADR-0003.
///
/// `owner_pubkey` is the daemon's own 65-byte uncompressed secp256k1
/// pubkey (same encoding `wrap_recv` consumes). Decryption uses the
/// daemon's identity private key via [`unwrap_slfw`].
pub fn wrap_slfw(owner_pubkey: &[u8], filename: &str, plaintext: &[u8]) -> Result<Envelope> {
    let k = generate_key();
    let header = EnvelopeHeader {
        true_length: plaintext.len() as u64,
        filename: filename.to_string(),
    };
    let body = pad_body(&header, plaintext)?;
    let sealed = aes_seal(&k, &body);
    let wrapped_key = ecies_wrap(owner_pubkey, k.as_bytes())?;
    let mut out = Vec::with_capacity(4 + wrapped_key.len() + sealed.len());
    out.extend_from_slice(&SLFW_TAG);
    out.extend_from_slice(&wrapped_key);
    out.extend_from_slice(&sealed);
    Ok(Envelope { bytes: out })
}

/// Unwrap a `SLFW` envelope using the owner's identity private key.
/// Same ECIES-unwrap-then-AES-decrypt as [`unwrap_recv`]; the only
/// difference is the tag check.
pub fn unwrap_slfw(my_private_key: &[u8], blob: &[u8]) -> Result<UnwrappedBlob> {
    let (tag, body) = split_tag(blob)?;
    if tag != SLFW_TAG {
        return Err(CryptoError::UnknownTag(tag));
    }
    const ECIES_WRAPPED_KEY_LEN: usize = 32 + 97;
    if body.len() < ECIES_WRAPPED_KEY_LEN {
        return Err(CryptoError::BlobTooShort(body.len(), ECIES_WRAPPED_KEY_LEN));
    }
    let (wrapped_key, sealed) = body.split_at(ECIES_WRAPPED_KEY_LEN);
    let k_bytes = ecies_unwrap(my_private_key, wrapped_key)?;
    if k_bytes.len() != crate::sym::AES_KEY_LEN {
        return Err(CryptoError::EciesDecrypt);
    }
    let mut k_arr = [0u8; crate::sym::AES_KEY_LEN];
    k_arr.copy_from_slice(&k_bytes);
    let k = SymKey(k_arr);
    let decrypted = aes_open(&k, sealed)?;
    decode_body(&decrypted)
}

/// Wrap `plaintext` as a RECV envelope targeted at `recipient_pubkey`.
/// Mints a fresh `K` internally; returns the envelope. The caller
/// does NOT need to keep K (only the recipient can recover it from
/// the ECIES wrapper).
pub fn wrap_recv(recipient_pubkey: &[u8], filename: &str, plaintext: &[u8]) -> Result<Envelope> {
    let k = generate_key();
    let header = EnvelopeHeader {
        true_length: plaintext.len() as u64,
        filename: filename.to_string(),
    };
    let body = pad_body(&header, plaintext)?;
    let sealed = aes_seal(&k, &body);
    let wrapped_key = ecies_wrap(recipient_pubkey, k.as_bytes())?;
    let mut out = Vec::with_capacity(4 + wrapped_key.len() + sealed.len());
    out.extend_from_slice(&RECV_TAG);
    out.extend_from_slice(&wrapped_key);
    out.extend_from_slice(&sealed);
    Ok(Envelope { bytes: out })
}

/// Unwrap a SELF envelope. The caller resolves `K` from the
/// keystore using the fingerprint carried in the envelope header.
///
/// Returns `UnwrappedBlob { filename, plaintext }` with padding
/// stripped. Fails fast if the fingerprint doesn't match the key.
pub fn unwrap_self(key: &SymKey, blob: &[u8]) -> Result<UnwrappedBlob> {
    let (tag, body) = split_tag(blob)?;
    if tag != SELF_TAG {
        return Err(CryptoError::UnknownTag(tag));
    }
    if body.len() < FINGERPRINT_LEN {
        return Err(CryptoError::BlobTooShort(body.len(), FINGERPRINT_LEN));
    }
    let (fp_in_blob, sealed) = body.split_at(FINGERPRINT_LEN);
    let fp_of_key = key_fingerprint(key.as_bytes());
    if fp_in_blob != fp_of_key {
        return Err(CryptoError::FingerprintMismatch);
    }
    let decrypted = aes_open(key, sealed)?;
    decode_body(&decrypted)
}

/// Unwrap a RECV envelope using the recipient's 32-byte private key.
pub fn unwrap_recv(my_private_key: &[u8], blob: &[u8]) -> Result<UnwrappedBlob> {
    let (tag, body) = split_tag(blob)?;
    if tag != RECV_TAG {
        return Err(CryptoError::UnknownTag(tag));
    }
    // ECIES ciphertext layout per `ecies` crate: 65-byte ephemeral
    // pubkey || tag/body. We don't need to parse — just hand the
    // whole wrapper to `ecies_unwrap`. But we have to know where
    // the AES-GCM wrapper ends.
    //
    // ECIES overhead for the `ecies` crate v0.2 is a fixed 97 bytes
    // on top of the wrapped plaintext length — measured empirically
    // (`ecies::encrypt(pk, &zeros_of_len_N).len() == N + 97`). For a
    // 32-byte K that gives 32 + 97 = 129 bytes. If the ecies crate
    // bumps a major and changes its wire format, this constant
    // breaks round-trip and the tests catch it in CI.
    const ECIES_WRAPPED_KEY_LEN: usize = 32 + 97;
    if body.len() < ECIES_WRAPPED_KEY_LEN {
        return Err(CryptoError::BlobTooShort(body.len(), ECIES_WRAPPED_KEY_LEN));
    }
    let (wrapped_key, sealed) = body.split_at(ECIES_WRAPPED_KEY_LEN);
    let k_bytes = ecies_unwrap(my_private_key, wrapped_key)?;
    if k_bytes.len() != crate::sym::AES_KEY_LEN {
        return Err(CryptoError::EciesDecrypt);
    }
    let mut k_arr = [0u8; crate::sym::AES_KEY_LEN];
    k_arr.copy_from_slice(&k_bytes);
    let k = SymKey(k_arr);
    let decrypted = aes_open(&k, sealed)?;
    decode_body(&decrypted)
}

fn split_tag(blob: &[u8]) -> Result<([u8; 4], &[u8])> {
    if blob.len() < 4 {
        return Err(CryptoError::BlobTooShort(blob.len(), 4));
    }
    let mut tag = [0u8; 4];
    tag.copy_from_slice(&blob[..4]);
    Ok((tag, &blob[4..]))
}

fn pad_body(header: &EnvelopeHeader, plaintext: &[u8]) -> Result<Vec<u8>> {
    let hdr = header.encode()?;
    let body_natural = hdr.len() + plaintext.len();
    let target = bucket_size(body_natural as u64) as usize;
    let mut body = Vec::with_capacity(target);
    body.extend_from_slice(&hdr);
    body.extend_from_slice(plaintext);
    body.resize(target, 0);
    Ok(body)
}

fn decode_body(decrypted: &[u8]) -> Result<UnwrappedBlob> {
    let (header, tail) = EnvelopeHeader::decode(decrypted)?;
    let n = header.true_length as usize;
    if n > tail.len() {
        return Err(CryptoError::PaddingCorrupt {
            declared: header.true_length,
            padded: tail.len(),
        });
    }
    Ok(UnwrappedBlob {
        filename: header.filename,
        plaintext: tail[..n].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sym::generate_key;
    use ecies::utils::generate_keypair;

    #[test]
    fn bucket_sizes_cover_the_tiered_set() {
        assert_eq!(bucket_size(0), 1 << 10);
        assert_eq!(bucket_size(1), 1 << 10);
        assert_eq!(bucket_size(1024), 1 << 10);
        assert_eq!(bucket_size(1025), 1 << 12);
        assert_eq!(bucket_size(1 << 12), 1 << 12);
        assert_eq!(bucket_size((1 << 12) + 1), 1 << 16);
        assert_eq!(bucket_size(1 << 24), 1 << 24);
        assert_eq!(bucket_size((1 << 24) + 1), 1 << 28);
        // Over 4 GiB: step by 16 MiB.
        let huge = (1u64 << 32) + 1;
        assert_eq!(bucket_size(huge) % (1 << 24), 0);
        assert!(bucket_size(huge) >= huge);
    }

    #[test]
    fn self_round_trip() {
        let k = generate_key();
        let (env, fp) = wrap_self(&k, "notes.txt", b"hello world").unwrap();
        assert_eq!(fp, key_fingerprint(k.as_bytes()));
        let unw = unwrap_self(&k, &env.bytes).unwrap();
        assert_eq!(unw.filename, "notes.txt");
        assert_eq!(unw.plaintext, b"hello world");
    }

    #[test]
    fn self_envelope_length_is_bucket_sized() {
        let k = generate_key();
        let (env, _) = wrap_self(&k, "x", b"small").unwrap();
        // Length = 4 (tag) + 32 (fingerprint) + 12 (nonce) + bucket + 16 (gcm tag).
        let body_natural = EnvelopeHeader {
            true_length: b"small".len() as u64,
            filename: "x".into(),
        }
        .encode()
        .unwrap()
        .len()
            + b"small".len();
        let bucket = bucket_size(body_natural as u64) as usize;
        assert_eq!(env.bytes.len(), 4 + 32 + 12 + bucket + 16);
    }

    #[test]
    fn self_envelope_lengths_dont_leak_true_size_within_bucket() {
        let k = generate_key();
        let a = wrap_self(&k, "a.bin", &[0u8; 100]).unwrap().0;
        let b = wrap_self(&k, "a.bin", &[0u8; 200]).unwrap().0;
        // Same bucket (1 KiB) -> same envelope length regardless of real size.
        assert_eq!(a.bytes.len(), b.bytes.len());
    }

    #[test]
    fn self_wrong_key_rejected_by_fingerprint() {
        let k1 = generate_key();
        let k2 = generate_key();
        let (env, _) = wrap_self(&k1, "x", b"...").unwrap();
        assert!(matches!(
            unwrap_self(&k2, &env.bytes),
            Err(CryptoError::FingerprintMismatch)
        ));
    }

    #[test]
    fn self_wrong_tag_rejected() {
        let k = generate_key();
        let (mut env, _) = wrap_self(&k, "x", b"...").unwrap();
        env.bytes[0] = b'R'; // "RELF" — unknown
        assert!(matches!(
            unwrap_self(&k, &env.bytes),
            Err(CryptoError::UnknownTag(_))
        ));
    }

    #[test]
    fn recv_round_trip() {
        let (sk, pk) = generate_keypair();
        let sk_bytes = sk.serialize().to_vec();
        let pk_bytes = pk.serialize().to_vec();
        let env = wrap_recv(&pk_bytes, "greeting.txt", b"hi Bob").unwrap();
        let unw = unwrap_recv(&sk_bytes, &env.bytes).unwrap();
        assert_eq!(unw.filename, "greeting.txt");
        assert_eq!(unw.plaintext, b"hi Bob");
    }

    #[test]
    fn recv_wrong_recipient_rejected() {
        let (_sk1, pk1) = generate_keypair();
        let (sk2, _pk2) = generate_keypair();
        let env = wrap_recv(&pk1.serialize(), "x", b"...").unwrap();
        assert!(matches!(
            unwrap_recv(&sk2.serialize(), &env.bytes),
            Err(CryptoError::EciesDecrypt)
        ));
    }

    #[test]
    fn recv_rejects_self_tag() {
        let k = generate_key();
        let (env, _) = wrap_self(&k, "x", b"...").unwrap();
        let (sk, _) = generate_keypair();
        assert!(matches!(
            unwrap_recv(&sk.serialize(), &env.bytes),
            Err(CryptoError::UnknownTag(SELF_TAG))
        ));
    }

    #[test]
    fn filename_can_be_unicode() {
        let k = generate_key();
        let (env, _) = wrap_self(&k, "日本語.txt", b"content").unwrap();
        let unw = unwrap_self(&k, &env.bytes).unwrap();
        assert_eq!(unw.filename, "日本語.txt");
    }

    #[test]
    fn filename_with_nul_rejected() {
        let k = generate_key();
        assert!(matches!(
            wrap_self(&k, "bad\0name", b""),
            Err(CryptoError::NulInFilename)
        ));
    }

    #[test]
    fn tamper_in_body_detected() {
        let k = generate_key();
        let (mut env, _) = wrap_self(&k, "x", b"hello").unwrap();
        let last = env.bytes.len() - 1;
        env.bytes[last] ^= 1;
        assert!(matches!(
            unwrap_self(&k, &env.bytes),
            Err(CryptoError::AeadDecrypt)
        ));
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let k = generate_key();
        let (env, _) = wrap_self(&k, "empty", b"").unwrap();
        let unw = unwrap_self(&k, &env.bytes).unwrap();
        assert!(unw.plaintext.is_empty());
    }

    // --- SLFW tests (ADR-0003) ---

    #[test]
    fn slfw_round_trip() {
        let (sk, pk) = generate_keypair();
        let env = wrap_slfw(&pk.serialize(), "notes.txt", b"my own notes").unwrap();
        assert_eq!(&env.bytes[..4], &SLFW_TAG);
        let unw = unwrap_slfw(&sk.serialize(), &env.bytes).unwrap();
        assert_eq!(unw.filename, "notes.txt");
        assert_eq!(unw.plaintext, b"my own notes");
    }

    #[test]
    fn slfw_rejects_wrong_privkey() {
        let (_sk1, pk1) = generate_keypair();
        let (sk2, _pk2) = generate_keypair();
        let env = wrap_slfw(&pk1.serialize(), "x", b"...").unwrap();
        assert!(matches!(
            unwrap_slfw(&sk2.serialize(), &env.bytes),
            Err(CryptoError::EciesDecrypt)
        ));
    }

    #[test]
    fn slfw_rejects_self_tag() {
        let k = generate_key();
        let (env, _) = wrap_self(&k, "x", b"...").unwrap();
        let (sk, _) = generate_keypair();
        assert!(matches!(
            unwrap_slfw(&sk.serialize(), &env.bytes),
            Err(CryptoError::UnknownTag(SELF_TAG))
        ));
    }

    #[test]
    fn slfw_and_recv_differ_only_in_tag() {
        // Both wrap K via ECIES to the recipient pubkey; the AES-GCM
        // body shape is identical. Guarding this symmetry means a
        // future refactor can collapse the two code paths safely.
        let (_sk, pk) = generate_keypair();
        let slfw = wrap_slfw(&pk.serialize(), "x", b"abc").unwrap();
        let recv = wrap_recv(&pk.serialize(), "x", b"abc").unwrap();
        assert_eq!(slfw.bytes.len(), recv.bytes.len());
        assert_eq!(&slfw.bytes[..4], &SLFW_TAG);
        assert_eq!(&recv.bytes[..4], &RECV_TAG);
    }

    #[test]
    fn slfw_envelope_length_is_bucket_sized() {
        let (_sk, pk) = generate_keypair();
        let env = wrap_slfw(&pk.serialize(), "x", b"small").unwrap();
        // tag(4) + ECIES_wrap(32+97=129) + nonce(12) + bucket + gcm_tag(16).
        let body_natural = EnvelopeHeader {
            true_length: b"small".len() as u64,
            filename: "x".into(),
        }
        .encode()
        .unwrap()
        .len()
            + b"small".len();
        let bucket = bucket_size(body_natural as u64) as usize;
        assert_eq!(env.bytes.len(), 4 + 129 + 12 + bucket + 16);
    }
}
