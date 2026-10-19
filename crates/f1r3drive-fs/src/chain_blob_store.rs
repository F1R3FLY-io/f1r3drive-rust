//! On-chain [`BlobStore`] backed by the Fs agent.
//!
//! Composes `f1r3drive-client` (gRPC) with `f1r3drive-rho` (snippet
//! generation) to persist / retrieve blobs under a flat on-chain
//! bundle dir. Each blob maps to one file whose name is
//! `<prefix>_<channel_name>`:
//!
//! - `put`: `dir_create_file` (truncate-or-create via `w+` mode) +
//!   `dir_write_file_at(offset=0)`.
//! - `get`: chunked `dir_read_file_at(offset, MAX_READ_BYTES)` loop,
//!   appending each chunk until a short read signals EOF. Server
//!   caps individual reads at `MAX_READ_BYTES = 64 MiB`; the loop
//!   handles arbitrarily large blobs.
//! - `list`: `dir_entries` on the bundle dir, filtered to names
//!   starting with `<prefix>_`.
//! - `delete`: `dir_remove_file`. The daemon reports success on
//!   admission + propose; the Fs agent's own reply isn't surfaced
//!   through `run_mutating` yet, so `BlobStore::delete` is
//!   effectively idempotent whether or not the entry existed —
//!   matches the trait contract either way.
//!
//! All ops serialize through a single tokio mutex on the shared
//! `NodeClient`. The mount-side ACL and envelope-encryption live
//! above us in `ExtensionFs`; this layer is content-opaque.

use std::sync::Arc;

use tokio::runtime::Handle;
use tracing::{error, warn};

use f1r3drive_client::{ClientError, DeployToSign, ExploratoryResult, KeyPair, NodeClient};
use f1r3drive_rho::{
    decode_reply, par_as_bytes, par_as_list, par_as_stat_record, FsReply, Snippet, SnippetBuilder,
};

use crate::blob_store::{compose_channel, validate_prefix, BlobError, BlobResult, BlobStore};

/// Server-side read cap (`MAX_READ_BYTES` in f1r3node-rust's io
/// layer). We request this much on every `get`; anything larger would
/// need chunking (future slice).
const MAX_READ_BYTES: u64 = 64 * 1024 * 1024;

/// Fs-agent-backed [`BlobStore`].
pub struct ChainBlobStore {
    runtime: Handle,
    client: Arc<tokio::sync::Mutex<NodeClient>>,
    builder: SnippetBuilder,
    signer: KeyPair,
    shard_id: String,
    manual_propose: bool,
    /// Name of the bundle dir holding every blob (e.g. `"root"`). The
    /// Fs agent must have this dir provisioned at genesis so
    /// `openDir(bundle_dir, {r+})` succeeds.
    bundle_dir: String,
}

impl ChainBlobStore {
    /// Build a chain-backed blob store. The `signer` must have write
    /// rights on `bundle_dir` under the Fs agent's ACL — the daemon
    /// uses it for every `put`/`delete` deploy.
    pub fn new(
        runtime: Handle,
        client: NodeClient,
        signer: KeyPair,
        shard_id: String,
        manual_propose: bool,
        bundle_dir: String,
        fs_urn_override: Option<String>,
    ) -> Self {
        let builder = match fs_urn_override {
            Some(u) => SnippetBuilder::new().with_fs_urn(u),
            None => SnippetBuilder::new(),
        };
        Self {
            runtime,
            client: Arc::new(tokio::sync::Mutex::new(client)),
            builder,
            signer,
            shard_id,
            manual_propose,
            bundle_dir,
        }
    }

    /// Run a read-only snippet via `exploratory_deploy` and decode
    /// the reply. See [`crate::fs::F1r3Fs::run_readonly_snippet`] for
    /// why we serialize on the client mutex.
    fn run_readonly(&self, snippet: Snippet) -> BlobResult<FsReply> {
        let term = snippet.term().to_string();
        let outcome = self.runtime.block_on(async move {
            let mut guard = self.client.lock().await;
            guard.exploratory_deploy(&term, "", false).await
        });
        match outcome {
            Ok(ExploratoryResult { pars, .. }) => decode_reply(&pars).map_err(|e| {
                error!(?e, "reply decode failed");
                BlobError::Backend(format!("decode: {e:?}"))
            }),
            Err(e) => Err(client_err(e)),
        }
    }

    /// Sign + submit a mutating snippet and (unless `manual_propose`)
    /// trigger a block. We don't surface the Fs agent's own reply —
    /// retrieving it would need a `getDataAtName` round-trip against
    /// the deploy's return channel, which this crate doesn't do yet.
    /// Admission + propose success is all the caller gets.
    fn run_mutating(&self, snippet: Snippet) -> BlobResult<()> {
        let term = snippet.term().to_string();
        let shard_id = self.shard_id.clone();
        let manual_propose = self.manual_propose;
        let client = self.client.clone();
        let signer = self.signer.clone();

        let outcome = self.runtime.block_on(async move {
            let mut guard = client.lock().await;
            let mut to_sign = DeployToSign::new_now(term, shard_id);
            match guard.status().await {
                Ok(s) => to_sign.valid_after_block_number = s.last_finalized_block_number.max(0),
                Err(e) if e.is_unimplemented() => {
                    tracing::debug!("node has no status RPC; using valid_after_block_number=0");
                }
                Err(e) => return Err(e),
            }
            let signed = to_sign
                .sign(&signer)
                .map_err(|e| ClientError::Sign(e.to_string()))?;
            guard.do_deploy(signed).await?;
            if !manual_propose {
                if let Err(e) = guard.propose(false).await {
                    warn!(err = ?e, "propose after deploy failed; deploy remains in pool");
                }
            }
            Ok::<(), ClientError>(())
        });

        outcome.map_err(client_err)
    }
}

fn client_err(e: ClientError) -> BlobError {
    warn!(err = ?e, "node client call failed");
    BlobError::Backend(format!("{e:?}"))
}

impl BlobStore for ChainBlobStore {
    fn put(&self, prefix: &str, channel_name: &str, bytes: &[u8]) -> BlobResult<()> {
        validate_prefix(prefix)?;
        let rel = compose_channel(prefix, channel_name);
        // `w+` mode on the Fs agent is POSIX truncate-or-create, so
        // dir_create_file idempotently resets the file to zero length.
        // Then write-at-0 lays down the new payload.
        self.run_mutating(self.builder.dir_create_file(&self.bundle_dir, &rel))?;
        self.run_mutating(
            self.builder
                .dir_write_file_at(&self.bundle_dir, &rel, 0, bytes),
        )
    }

    fn get(&self, prefix: &str, channel_name: &str) -> BlobResult<Option<Vec<u8>>> {
        validate_prefix(prefix)?;
        let rel = compose_channel(prefix, channel_name);
        // Chunked read: the server caps each `dir_read_file_at` call
        // at `MAX_READ_BYTES = 64 MiB`. For larger blobs we loop,
        // appending each chunk, until a short read tells us we hit
        // the end. The first chunk also carries the NotFound signal
        // if the entry doesn't exist.
        let mut out: Vec<u8> = Vec::new();
        loop {
            let offset = out.len() as u64;
            let snippet =
                self.builder
                    .dir_read_file_at(&self.bundle_dir, &rel, offset, MAX_READ_BYTES);
            match self.run_readonly(snippet)? {
                FsReply::Ok { payload } => {
                    let bytes = payload
                        .first()
                        .and_then(par_as_bytes)
                        .unwrap_or(&[])
                        .to_vec();
                    let n = bytes.len() as u64;
                    out.extend_from_slice(&bytes);
                    if n < MAX_READ_BYTES {
                        // Short read = EOF. For files whose length is
                        // an exact multiple of MAX_READ_BYTES, one
                        // extra zero-byte call lands here with n == 0.
                        break;
                    }
                }
                FsReply::Err(e) if e.code == f1r3drive_rho::FSERR_NOT_FOUND => {
                    if offset == 0 {
                        return Ok(None);
                    }
                    // Partial read followed by NotFound would be a
                    // concurrent-delete race on the server. Treat
                    // what we have as the blob.
                    warn!(prefix, channel_name, "concurrent delete during chunked get");
                    break;
                }
                FsReply::Err(e) => {
                    return Err(BlobError::Backend(format!("{}: {}", e.code, e.message)));
                }
            }
        }
        Ok(Some(out))
    }

    fn list(&self, prefix: &str) -> BlobResult<Vec<String>> {
        validate_prefix(prefix)?;
        let snippet = self.builder.dir_entries(&self.bundle_dir);
        match self.run_readonly(snippet)? {
            FsReply::Ok { payload } => {
                let rows = payload
                    .first()
                    .and_then(par_as_list)
                    .cloned()
                    .unwrap_or_default();
                let names: Vec<String> = rows
                    .iter()
                    .filter_map(par_as_stat_record)
                    .filter_map(|rec| rec.name)
                    .collect();
                Ok(filter_channels_by_prefix(&names, prefix))
            }
            FsReply::Err(e) => Err(BlobError::Backend(format!("{}: {}", e.code, e.message))),
        }
    }

    fn delete(&self, prefix: &str, channel_name: &str) -> BlobResult<()> {
        validate_prefix(prefix)?;
        let rel = compose_channel(prefix, channel_name);
        // `run_mutating` doesn't surface the Fs agent's own reply, so
        // we can't distinguish NotFound from other errors post-admission.
        // The BlobStore contract already says delete is idempotent; a
        // deploy for a missing file is harmless (the Fs agent returns
        // FSERR_NOT_FOUND, which we don't observe).
        self.run_mutating(self.builder.dir_remove_file(&self.bundle_dir, &rel))
    }
}

/// Filter a flat list of bundle-dir filenames to the subset owned by
/// `prefix`, stripping the `<prefix>_` leader so the caller sees bare
/// channel names. Factored out so the filtering logic is testable
/// without a live shard.
fn filter_channels_by_prefix(all_names: &[String], prefix: &str) -> Vec<String> {
    let needle = format!("{prefix}_");
    all_names
        .iter()
        .filter_map(|n| n.strip_prefix(&needle))
        .map(|s| s.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_channels_by_prefix_keeps_matching() {
        let prefix = "04".to_string() + &"ab".repeat(64);
        let other = "04".to_string() + &"cd".repeat(64);
        let names = vec![
            format!("{prefix}_deadbeef"),
            format!("{prefix}_cafef00d"),
            format!("{other}_babecafe"),
            "unrelated".to_string(),
        ];
        let mut out = filter_channels_by_prefix(&names, &prefix);
        out.sort();
        assert_eq!(out, vec!["cafef00d".to_string(), "deadbeef".to_string()]);
    }

    #[test]
    fn filter_channels_by_prefix_requires_underscore_separator() {
        // A full-prefix match without the underscore separator must
        // NOT be classified as owned by `prefix` — otherwise channel
        // names bleed between near-identical prefixes.
        let prefix = "04".to_string() + &"ab".repeat(64);
        let names = vec![
            // Same hex but no underscore separator — reject.
            format!("{prefix}deadbeef"),
            // Proper match — keep.
            format!("{prefix}_abcd"),
        ];
        assert_eq!(
            filter_channels_by_prefix(&names, &prefix),
            vec!["abcd".to_string()]
        );
    }

    #[test]
    fn filter_channels_empty_when_no_match() {
        let prefix = "04".to_string() + &"ab".repeat(64);
        let names = vec!["foo".to_string(), "bar_quux".to_string()];
        assert!(filter_channels_by_prefix(&names, &prefix).is_empty());
    }
}
