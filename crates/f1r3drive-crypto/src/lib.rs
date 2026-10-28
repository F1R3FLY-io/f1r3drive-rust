//! Client-side crypto for f1r3drive-rust extension mode.
//!
//! See `docs/architecture/ADR-0002-extension-design.md` for the
//! envelope formats and threat model. Nothing in this crate talks to
//! the chain; it's pure data in, pure data out. Mount-layer glue
//! wraps blobs on their way to `Fs.File.writeBytesAt` and unwraps
//! them on `Fs.File.bytesAt`.
//!
//! Primitives:
//! - [`sym`] — AES-256-GCM wrap, random nonce prepended.
//! - [`asym`] — ECIES over secp256k1 for wrapping a 32-byte symmetric
//!   key against a recipient pubkey.
//! - [`hash`] — Blake2b-256 for the SELF-blob key fingerprint.
//! - [`envelope`] — the SELF / RECV blob format: filename + length
//!   encrypted in a header, body padded to a bucket boundary.
//! - [`keystore`] — on-disk index at `~/.f1r3drive/keys/<hex>` mapping
//!   `hash(K)` to raw K.

pub mod asym;
pub mod envelope;
pub mod error;
pub mod hash;
pub mod keystore;
pub mod sym;

pub use asym::{ecies_unwrap, ecies_wrap};
pub use envelope::{
    bucket_size, unwrap_recv, unwrap_self, unwrap_slfw, wrap_recv, wrap_self, wrap_slfw, Envelope,
    EnvelopeHeader, UnwrappedBlob, RECV_TAG, SELF_TAG, SLFW_TAG,
};
pub use error::{CryptoError, Result};
pub use hash::{key_fingerprint, FINGERPRINT_LEN};
pub use keystore::Keystore;
pub use sym::{generate_key, SymKey, AES_KEY_LEN, GCM_NONCE_LEN};
