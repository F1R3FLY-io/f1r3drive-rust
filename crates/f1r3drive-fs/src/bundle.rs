//! Tar+gzip bundle format for listing-as-folder.
//!
//! When a seller renames a folder (e.g. `/<me>/myproject`) into
//! `/<me>/Paid transfer/<N>REV-myproject`, the daemon walks the
//! subtree, decrypts every nested blob, and hands the resulting
//! `(rel_path, bytes)` pairs to [`pack`]. The returned bytes get
//! wrapped in one SELF envelope under a fresh `K_listing` and stored
//! on-chain exactly like a single-file listing. On the buyer side,
//! `purchase_via_factory` runs [`unpack`] and writes each extracted
//! leaf as its own RECV envelope under the buyer's prefix, preserving
//! the rel-paths so the buyer's `readdir` rebuilds the folder tree.
//!
//! Format: a gzip-compressed POSIX tar stream. Both deps are pure
//! Rust (`flate2` with `rust_backend`, `tar` default). The daemon
//! owns both sides, so we don't rely on wider tar compatibility
//! beyond what `tar::Builder` and `tar::Archive` guarantee for each
//! other.

use std::io::{Read, Write};

use flate2::write::GzEncoder;
use flate2::Compression;

/// One leaf file in a bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleEntry {
    /// Slash-joined rel-path from the bundle's root (no leading `/`,
    /// no `..`, no empty segments).
    pub rel_path: String,
    pub bytes: Vec<u8>,
}

/// Errors from pack/unpack. Mapped to `FsError::Io` or
/// `InvalidArgument` by callers.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("bundle entry rel-path is empty, absolute, or contains '..': {0:?}")]
    InvalidPath(String),
    #[error("bundle I/O: {0}")]
    Io(#[from] std::io::Error),
}

pub type BundleResult<T> = Result<T, BundleError>;

fn validate_rel_path(rel: &str) -> BundleResult<()> {
    if rel.is_empty() || rel.starts_with('/') {
        return Err(BundleError::InvalidPath(rel.to_string()));
    }
    for seg in rel.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return Err(BundleError::InvalidPath(rel.to_string()));
        }
    }
    Ok(())
}

/// Pack entries into a single gzipped tar byte stream. Rejects empty
/// rel-paths, absolute paths, and `..` segments up front — the
/// daemon's own code generates these, but the validation guards
/// against a buyer unpacking a hostile seller bundle.
pub fn pack(entries: impl IntoIterator<Item = BundleEntry>) -> BundleResult<Vec<u8>> {
    let gz = GzEncoder::new(Vec::new(), Compression::default());
    let mut builder = tar::Builder::new(gz);
    for entry in entries {
        validate_rel_path(&entry.rel_path)?;
        let mut header = tar::Header::new_gnu();
        header.set_size(entry.bytes.len() as u64);
        // Regular file; mode mirrors `attr_file_empty`.
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder.append_data(&mut header, &entry.rel_path, entry.bytes.as_slice())?;
    }
    let gz = builder.into_inner()?;
    let bytes = gz.finish()?;
    Ok(bytes)
}

/// Unpack a bundle. Returns a flat vec of leaf files; intermediate
/// directories are implied by rel-paths and get synthesized on the
/// buyer side by the normal `readdir` logic.
///
/// Rejects path traversal and symlinks on read. The buyer blindly
/// trusts the seller for payload bytes, but we're strict about path
/// shape so a malicious bundle can't write outside the buyer's
/// prefix.
pub fn unpack(bytes: &[u8]) -> BundleResult<Vec<BundleEntry>> {
    let gz = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(gz);
    // Deny escaping entries up-front; `set_overwrite(false)` keeps
    // us from stomping sibling files but we're not using the
    // `unpack` path anyway — reading entries manually gives us
    // explicit control over the rel-path validation.
    let mut out = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        // Reject non-regular entry types (symlinks, hardlinks,
        // devices, directories — directories are implicit for us).
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let path = entry.path()?;
        let rel = path.to_string_lossy().into_owned();
        validate_rel_path(&rel)?;
        let mut bytes = Vec::with_capacity(entry.header().size()? as usize);
        entry.read_to_end(&mut bytes)?;
        out.push(BundleEntry {
            rel_path: rel,
            bytes,
        });
    }
    Ok(out)
}

/// Convenience: finish the gzip stream explicitly so clippy sees
/// the `Write::flush` path exercised (silences a false positive).
#[allow(dead_code)]
fn _flush_hint() -> std::io::Result<()> {
    let mut v: Vec<u8> = Vec::new();
    v.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(rel: &str, body: &[u8]) -> BundleEntry {
        BundleEntry {
            rel_path: rel.to_string(),
            bytes: body.to_vec(),
        }
    }

    #[test]
    fn pack_unpack_round_trip_preserves_paths_and_content() {
        let input = vec![
            e("README", b"hi"),
            e("docs/intro.md", b"# intro"),
            e("docs/misc/scratch.txt", b"notes"),
        ];
        let packed = pack(input.clone()).unwrap();
        let got = unpack(&packed).unwrap();
        assert_eq!(got, input);
    }

    #[test]
    fn pack_rejects_absolute_path() {
        let r = pack(vec![e("/etc/passwd", b"evil")]);
        assert!(matches!(r, Err(BundleError::InvalidPath(_))));
    }

    #[test]
    fn pack_rejects_parent_segment() {
        let r = pack(vec![e("safe/../../etc/passwd", b"evil")]);
        assert!(matches!(r, Err(BundleError::InvalidPath(_))));
    }

    #[test]
    fn pack_rejects_empty_rel_path() {
        let r = pack(vec![e("", b"nope")]);
        assert!(matches!(r, Err(BundleError::InvalidPath(_))));
    }

    #[test]
    fn validate_rel_path_catches_edge_cases() {
        // Covers the defense-in-depth check that `unpack` applies
        // to every entry. The pack side also rejects these via
        // `tar::Builder`'s own guards, so a hostile bundle can
        // only be assembled by hand-rolling tar bytes outside this
        // module — the validation covers that case.
        assert!(matches!(
            validate_rel_path("/absolute"),
            Err(BundleError::InvalidPath(_))
        ));
        assert!(matches!(
            validate_rel_path("good/../bad"),
            Err(BundleError::InvalidPath(_))
        ));
        assert!(matches!(
            validate_rel_path(""),
            Err(BundleError::InvalidPath(_))
        ));
        assert!(matches!(
            validate_rel_path("a//b"),
            Err(BundleError::InvalidPath(_))
        ));
        assert!(validate_rel_path("ok/path.txt").is_ok());
    }

    #[test]
    fn empty_bundle_round_trips() {
        let packed = pack(Vec::<BundleEntry>::new()).unwrap();
        let got = unpack(&packed).unwrap();
        assert!(got.is_empty());
    }
}
