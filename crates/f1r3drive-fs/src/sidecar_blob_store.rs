//! `SidecarBlobStore` — HTTP-first `BlobStore` decorator.
//!
//! Routes `BlobStore::get` through the per-node `file-read-service`
//! sidecar (`scripts/file-read-service` in f1r3node-rust) over
//! loopback HTTP, falling back to the inner [`BlobStore`] (typically
//! [`ChainBlobStore`]) when the sidecar is unreachable or returns
//! anything that isn't a definitive 200/404.
//!
//! Writes (`put` / `delete`) and the enumeration path (`list`) go
//! straight through to the inner store — the sidecar is a read-only
//! HTTP surface over local disk, intended for low-latency reads of
//! bundle entries that consensus-mode WAL replay has already
//! materialised on every node.
//!
//! See `feature/file-read-service` in f1r3node-rust for the server-
//! side implementation and the HTTP API shape (route:
//! `GET /files/{logical}?sub_rel={rel}&offset=N&length=M`).

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, trace, warn};

use crate::blob_store::{compose_channel, validate_prefix, BlobError, BlobResult, BlobStore};

/// Server-side read cap on each `GET /files/...` request. Matches
/// `MAX_READ_BYTES` in both f1r3node-rust's io layer and
/// `ChainBlobStore`'s chunked `dir_read_file_at` loop.
const MAX_READ_BYTES: u64 = 64 * 1024 * 1024;

pub struct SidecarBlobStore {
    base_url: String,
    bundle_dir: String,
    http: ureq::Agent,
    inner: Arc<dyn BlobStore>,
}

impl SidecarBlobStore {
    /// Build a sidecar-first blob store.
    ///
    /// - `base_url`: `http://127.0.0.1:9810` (no trailing slash). The
    ///   daemon's co-located sidecar.
    /// - `bundle_dir`: operator-declared logical name for the bundle
    ///   root — same string passed to `--mount-source` and to the
    ///   `ChainBlobStore` constructor. The sidecar resolves this to
    ///   a path via the node's HOCON `consensus-static-dirs` /
    ///   `oracle-static-dirs` map.
    /// - `inner`: the `BlobStore` that handles writes + list + the
    ///   fallback path when the sidecar can't serve a `get`.
    pub fn new(base_url: String, bundle_dir: String, inner: Arc<dyn BlobStore>) -> Self {
        let http = ureq::Agent::config_builder()
            // Short bias — if the sidecar isn't healthy we'd rather
            // fail over to gRPC than hang a FUSE callback. The chain
            // path still takes seconds, so even a 1s connect probe
            // is noise next to the fallback cost.
            .timeout_connect(Some(Duration::from_millis(500)))
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into();
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            bundle_dir,
            http,
            inner,
        }
    }

    /// Build the GET URL for a (prefix, channel) read window.
    fn url(&self, rel: &str, offset: u64, length: u64) -> String {
        format!(
            "{}/files/{}?sub_rel={}&offset={}&length={}",
            self.base_url,
            urlencoding::encode(&self.bundle_dir),
            urlencoding::encode(rel),
            offset,
            length,
        )
    }

    /// Build the directory-listing URL (prefix-filtered).
    fn list_url(&self, prefix: &str) -> String {
        format!(
            "{}/list/{}?prefix={}",
            self.base_url,
            urlencoding::encode(&self.bundle_dir),
            urlencoding::encode(&format!("{prefix}_")),
        )
    }

    /// Attempt one chunked GET. Returns `Ok(Some(bytes))` on 200,
    /// `Ok(None)` on a definitive 404, or `Err` for anything the
    /// caller should fall back on. `Err(BlobError::Backend(_))` is
    /// used for every fallback-worthy outcome so the caller can
    /// hand the request to the inner store uniformly.
    fn try_get_chunk(
        &self,
        rel: &str,
        offset: u64,
        length: u64,
    ) -> Result<Option<Vec<u8>>, BlobError> {
        let url = self.url(rel, offset, length);
        trace!(url, "sidecar read");
        match self.http.get(&url).call() {
            Ok(mut resp) => {
                let status = resp.status();
                if status == 404 {
                    return Ok(None);
                }
                if status != 200 {
                    return Err(BlobError::Backend(format!(
                        "sidecar returned HTTP {status}"
                    )));
                }
                let body = resp
                    .body_mut()
                    .read_to_vec()
                    .map_err(|e| BlobError::Backend(format!("sidecar body read: {e:?}")))?;
                Ok(Some(body))
            }
            Err(e) => Err(BlobError::Backend(format!("sidecar transport: {e:?}"))),
        }
    }
}

impl BlobStore for SidecarBlobStore {
    fn put(&self, prefix: &str, channel_name: &str, bytes: &[u8]) -> BlobResult<()> {
        self.inner.put(prefix, channel_name, bytes)
    }

    fn get(&self, prefix: &str, channel_name: &str) -> BlobResult<Option<Vec<u8>>> {
        validate_prefix(prefix)?;
        let rel = compose_channel(prefix, channel_name);

        // Chunked loop mirroring `ChainBlobStore::get`. For blobs
        // under 64 MiB this is one request. For larger blobs we
        // concatenate until we get a short-read.
        let mut out: Vec<u8> = Vec::new();
        loop {
            let offset = out.len() as u64;
            match self.try_get_chunk(&rel, offset, MAX_READ_BYTES) {
                Ok(Some(chunk)) => {
                    let n = chunk.len() as u64;
                    if offset == 0 && chunk.is_empty() && n == 0 {
                        // Empty-file: sidecar returned 200 with zero
                        // bytes. Treat as a legitimate empty blob
                        // (not NotFound). Second iteration would
                        // yield the same, so we break here.
                        return Ok(Some(out));
                    }
                    out.extend_from_slice(&chunk);
                    if n < MAX_READ_BYTES {
                        // Short read → EOF. For sizes exactly on
                        // the chunk boundary one extra zero-byte
                        // chunk lands here with n == 0.
                        return Ok(Some(out));
                    }
                }
                Ok(None) => {
                    if offset == 0 {
                        // Definitive 404 from the first chunk —
                        // sidecar is confident the blob doesn't
                        // exist. Don't fall back to the chain:
                        // consensus-mode replication guarantees
                        // every node has the same view, so a 404
                        // here would be a 404 at the chain too.
                        return Ok(None);
                    }
                    // Partial chunks followed by 404 → race with a
                    // concurrent delete. Return what we have, same
                    // as ChainBlobStore does.
                    warn!(
                        prefix,
                        channel_name, "concurrent delete during sidecar chunked get"
                    );
                    return Ok(Some(out));
                }
                Err(e) => {
                    // Transport / 5xx / unexpected status — the
                    // sidecar is sick. Fall back to the inner store
                    // for the WHOLE read (not just the current
                    // chunk) so we don't stitch together bytes from
                    // two different sources.
                    debug!(
                        err = ?e,
                        prefix,
                        channel_name,
                        "sidecar read failed; falling back to inner BlobStore"
                    );
                    return self.inner.get(prefix, channel_name);
                }
            }
        }
    }

    fn list(&self, prefix: &str) -> BlobResult<Vec<String>> {
        validate_prefix(prefix)?;
        // Try the sidecar's `/list/{logical}?prefix=<prefix>_` first.
        // Under consensus-mode caps the chain's `Dir.entries()` is
        // refused (stream backing is non-deterministic across
        // validators); the sidecar reads the local bundle dir and
        // returns a filename list. Falls back to the inner store on
        // any transport / non-200 outcome.
        let url = self.list_url(prefix);
        trace!(url, "sidecar list");
        let names: Vec<String> = match self.http.get(&url).call() {
            Ok(mut resp) => {
                let status = resp.status();
                if status != 200 {
                    debug!(status = status.as_u16(), "sidecar list non-200; falling back");
                    return self.inner.list(prefix);
                }
                let body = match resp.body_mut().read_to_vec() {
                    Ok(b) => b,
                    Err(e) => {
                        debug!(err = ?e, "sidecar list body read failed; falling back");
                        return self.inner.list(prefix);
                    }
                };
                match serde_json::from_slice::<Vec<String>>(&body) {
                    Ok(v) => v,
                    Err(e) => {
                        debug!(err = ?e, "sidecar list json decode failed; falling back");
                        return self.inner.list(prefix);
                    }
                }
            }
            Err(e) => {
                debug!(err = ?e, "sidecar list transport failed; falling back");
                return self.inner.list(prefix);
            }
        };
        // Sidecar returns full on-disk filenames (`<prefix>_<channel>`);
        // the BlobStore::list contract returns channel names (just the
        // suffix after `<prefix>_`). Strip the prefix.
        let pfx = format!("{prefix}_");
        Ok(names
            .into_iter()
            .filter_map(|n| n.strip_prefix(&pfx).map(|s| s.to_string()))
            .collect())
    }

    fn delete(&self, prefix: &str, channel_name: &str) -> BlobResult<()> {
        self.inner.delete(prefix, channel_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob_store::InMemoryBlobStore;
    use crate::extension_fs::PUBKEY_HEX_LEN;

    fn pk(seed: u8) -> String {
        let mut s = String::from("04");
        for _ in 0..64 {
            s.push_str(&format!("{seed:02x}"));
        }
        s.truncate(PUBKEY_HEX_LEN);
        s
    }

    #[test]
    fn delegates_put_delete_list_to_inner() {
        let inner = Arc::new(InMemoryBlobStore::new());
        let p = pk(0xab);
        inner.put(&p, "a", b"1").unwrap();
        inner.put(&p, "b", b"2").unwrap();

        // Unreachable sidecar — all non-get ops still work via
        // the delegated inner. (Get is tested in e2e with a real
        // sidecar; a mock HTTP server here would duplicate too
        // much ureq surface for little coverage.)
        let s = SidecarBlobStore::new(
            "http://127.0.0.1:1".to_string(),
            "root".to_string(),
            inner.clone(),
        );
        s.put(&p, "c", b"3").unwrap();
        let mut l = s.list(&p).unwrap();
        l.sort();
        assert_eq!(l, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
        s.delete(&p, "a").unwrap();
        assert!(inner.get(&p, "a").unwrap().is_none());
    }

    #[test]
    fn get_falls_back_when_sidecar_unreachable() {
        let inner = Arc::new(InMemoryBlobStore::new());
        let p = pk(0xab);
        inner.put(&p, "x", b"from-chain").unwrap();
        // Port 1 is reserved; the connect probe fails fast and we
        // route through the fallback.
        let s = SidecarBlobStore::new("http://127.0.0.1:1".to_string(), "root".to_string(), inner);
        assert_eq!(s.get(&p, "x").unwrap(), Some(b"from-chain".to_vec()));
    }

    #[test]
    fn url_construction_percent_encodes_bundle_and_rel() {
        let s = SidecarBlobStore::new(
            "http://host:9810".to_string(),
            "root/weird dir".to_string(),
            Arc::new(InMemoryBlobStore::new()),
        );
        let url = s.url("04ab_cd ef", 128, 1024);
        // Space + slash both get encoded.
        assert!(url.contains("sub_rel=04ab_cd%20ef"));
        assert!(url.contains("files/root%2Fweird%20dir"));
        assert!(url.ends_with("offset=128&length=1024"));
    }
}
