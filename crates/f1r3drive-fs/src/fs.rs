//! `F1r3Fs` — the `libfuse_t_rs::Filesystem` implementation.
//!
//! Each FUSE op compiles a Rholang snippet via
//! [`f1r3drive_rho::SnippetBuilder`], runs it via
//! [`f1r3drive_client::NodeClient::exploratory_deploy`] (read-only, no
//! block), and decodes the reply into the shape libfuse-t expects.
//!
//! fuse-t under the hood: libfuse-t presents the libfuse 2.9 high-level
//! C API. Mounting goes through [`libfuse_t_rs::spawn_mount`] /
//! [`libfuse_t_rs::mount`], which trampoline C callbacks into the trait
//! methods below.
//!
//! The daemon's trait methods are `&self` + `Send + Sync`, so the
//! client is behind a `tokio::sync::Mutex` and the tokio runtime
//! handle is cloned per-op.

use std::path::Path;
use std::sync::Arc;

use libfuse_t_rs::{
    DirEntry as FtDirEntry, FileAttr as FtFileAttr, FileKind, Filesystem, FsError as FtFsError,
    FsResult as FtFsResult,
};
use tokio::runtime::Handle;
use tracing::{error, trace};

use f1r3drive_client::{ClientError, DeployToSign, ExploratoryResult, NodeClient};
use f1r3drive_rho::{
    decode_reply, par_as_bytes, par_as_list, par_as_stat_record, FsReply, Snippet, SnippetBuilder,
    StatRecord,
};

use crate::config::FsConfig;

/// FUSE-side filesystem backed by the on-chain `Fs` agent.
pub struct F1r3Fs {
    runtime: Handle,
    client: Arc<tokio::sync::Mutex<NodeClient>>,
    config: FsConfig,
    builder: SnippetBuilder,
}

impl F1r3Fs {
    pub fn new(runtime: Handle, client: NodeClient, config: FsConfig) -> Self {
        let builder = match config.fs_urn_override.clone() {
            Some(u) => SnippetBuilder::new().with_fs_urn(u),
            None => SnippetBuilder::new(),
        };
        Self {
            runtime,
            client: Arc::new(tokio::sync::Mutex::new(client)),
            config,
            builder,
        }
    }

    /// Dispatch a snippet via `exploratory_deploy` and decode the reply.
    /// Blocks the current (fuser-callback) thread via the runtime handle.
    fn run_readonly_snippet(&self, snippet: Snippet) -> FtFsResult<FsReply> {
        // Hold the client mutex for the duration of the gRPC call so
        // concurrent reads SERIALIZE. The server reuses a single
        // kernel fd across concurrent openFile calls (per our pwrite
        // trace: 93 writes all land on raw_fd=53), which means
        // concurrent lseek+read on different Rholang-level fds race
        // on the same shared OS-fd cursor — a `seek(32768)+readN`
        // started under another deploy's `seek(0)` returns bytes from
        // offset 0. Serialization costs latency but is correct;
        // reads via positional `pread` would be the server-side
        // alternative.
        let term = snippet.term().to_string();
        let outcome = self.runtime.block_on(async move {
            let mut guard = self.client.lock().await;
            guard.exploratory_deploy(&term, "", false).await
        });
        match outcome {
            Ok(ExploratoryResult { pars, .. }) => decode_reply(&pars).map_err(|e| {
                error!(?e, "reply decode failed");
                FtFsError::Io
            }),
            Err(e) => Err(client_err_to_fs_error(e)),
        }
    }

    /// Sign + submit a mutating snippet, then (unless `manual_propose`)
    /// trigger a block creation. Returns `Ok(())` on admission + propose
    /// success. The deploy's actual Rholang reply isn't surfaced here —
    /// retrieving it would require a getDataAtName round-trip against
    /// the deploy's unforgeable return channel, which we defer.
    fn run_mutating_snippet(&self, snippet: Snippet) -> FtFsResult<()> {
        let Some(signer) = self.config.signer.as_ref().cloned() else {
            tracing::warn!("mutator FUSE op attempted on read-only daemon (no --key-file)");
            return Err(FtFsError::PermissionDenied);
        };

        let term = snippet.term().to_string();
        let shard_id = self.config.shard_id.clone();
        let manual_propose = self.config.manual_propose;
        let client = self.client.clone();

        let outcome = self.runtime.block_on(async move {
            let mut guard = client.lock().await;
            let mut to_sign = DeployToSign::new_now(term, shard_id);
            // valid_after must be close to the current LFB so the deploy
            // doesn't expire inside the server's lifespan window. If the
            // node's `status` RPC is unavailable (older server builds),
            // fall back to 0 — the deploy may expire quickly but we at
            // least get past admission on fresh shards.
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
                // Fire a propose and wait for the ack. Non-fatal:
                // admission succeeded, so the deploy is already in the
                // pool. A propose failure here is usually a transient
                // server-side condition (e.g. consensus state in flux,
                // another proposer round in progress). Log and move on;
                // the deploy will be included in a future block.
                if let Err(e) = guard.propose(false).await {
                    tracing::warn!(err = ?e, "propose after deploy failed; deploy remains in pool");
                }
            }
            Ok::<(), ClientError>(())
        });

        outcome.map_err(client_err_to_fs_error)
    }

    /// Turn a kernel-presented absolute path (`"/"`, `"/foo"`,
    /// `"/sub/x.txt"`) into the agent-relative path (`""`, `"foo"`,
    /// `"sub/x.txt"`).
    fn agent_rel(path: &Path) -> String {
        let s = path.to_string_lossy();
        s.trim_start_matches('/').to_string()
    }

    fn attr_from_stat(&self, rec: &StatRecord) -> FtFileAttr {
        let kind = match rec.kind.as_deref() {
            Some("directory") => FileKind::Directory,
            Some("file") => FileKind::Regular,
            _ => FileKind::Other,
        };
        let perm = rec.mode.unwrap_or(if kind == FileKind::Directory {
            0o755
        } else {
            0o644
        }) as u16;
        FtFileAttr {
            kind,
            perm,
            size: rec.size.unwrap_or(0),
            nlink: if kind == FileKind::Directory { 2 } else { 1 },
            uid: self.config.display_uid,
            gid: self.config.display_gid,
            atime: ms_to_system_time(rec.atime_ms),
            mtime: ms_to_system_time(rec.mtime_ms),
            ctime: ms_to_system_time(rec.ctime_ms),
            blocks: None,
            blksize: 4096,
        }
    }
}

fn ms_to_system_time(ms: Option<i64>) -> std::time::SystemTime {
    use std::time::{Duration, UNIX_EPOCH};
    match ms {
        Some(ms) if ms > 0 => UNIX_EPOCH + Duration::from_millis(ms as u64),
        _ => UNIX_EPOCH,
    }
}

fn fserr_code_to_fs_error(code: &str) -> FtFsError {
    use f1r3drive_rho::*;
    if code == FSERR_NOT_FOUND {
        FtFsError::NotFound
    } else if code == FSERR_PERM || code == FSERR_REVOKED {
        FtFsError::PermissionDenied
    } else if code == FSERR_BAD_ARG {
        FtFsError::InvalidArgument
    } else if code == FSERR_UNSUPPORTED {
        FtFsError::NotSupported
    } else if code == FSERR_ALREADY_EXISTS {
        FtFsError::AlreadyExists
    } else if code == FSERR_BUSY {
        FtFsError::Busy
    } else if code == FSERR_QUOTA_EXCEEDED {
        FtFsError::QuotaExceeded
    } else {
        FtFsError::Io
    }
}

fn client_err_to_fs_error(err: ClientError) -> FtFsError {
    tracing::warn!(?err, "node client call failed — reporting EIO");
    FtFsError::Io
}

impl Filesystem for F1r3Fs {
    fn init(&self) {
        tracing::info!(
            mount_source = %self.config.mount_source,
            "F1r3Fs mounted"
        );
    }

    fn getattr(&self, path: &Path) -> FtFsResult<FtFileAttr> {
        trace!(?path, "getattr");
        let rel = Self::agent_rel(path);
        let snippet = self.builder.dir_stat(&self.config.mount_source, &rel);
        match self.run_readonly_snippet(snippet)? {
            FsReply::Ok { payload } => {
                let rec = payload
                    .first()
                    .and_then(par_as_stat_record)
                    .ok_or(FtFsError::Io)?;
                Ok(self.attr_from_stat(&rec))
            }
            FsReply::Err(e) if rel.is_empty() => {
                // Root is special: if the mount source isn't provisioned
                // in the bundle, synthesize an empty read-only directory
                // so the mount can still come up. Any descendant lookup
                // still errors (we only mask the root case).
                tracing::debug!(
                    code = %e.code,
                    msg = %e.message,
                    "root bundle entry not provisioned — serving synthetic empty dir",
                );
                Ok(FtFileAttr::dir(
                    self.config.display_uid,
                    self.config.display_gid,
                ))
            }
            FsReply::Err(e) => Err(fserr_code_to_fs_error(&e.code)),
        }
    }

    fn readdir(&self, path: &Path) -> FtFsResult<Vec<FtDirEntry>> {
        trace!(?path, "readdir");
        let rel = Self::agent_rel(path);
        if !rel.is_empty() {
            // The current snippet only lists the mount root. Nested
            // `readdir` support lands with the full Dir ops migration.
            return Err(FtFsError::NotSupported);
        }
        let snippet = self.builder.dir_entries(&self.config.mount_source);
        match self.run_readonly_snippet(snippet)? {
            FsReply::Ok { payload } => {
                let rows = payload
                    .first()
                    .and_then(par_as_list)
                    .cloned()
                    .unwrap_or_default();
                let mut out = Vec::with_capacity(rows.len());
                let mut skipped = 0usize;
                for row in rows {
                    let Some(rec) = par_as_stat_record(&row) else {
                        skipped += 1;
                        continue;
                    };
                    let Some(name) = rec.name.clone() else {
                        skipped += 1;
                        continue;
                    };
                    let kind = match rec.kind.as_deref() {
                        Some("directory") => FileKind::Directory,
                        Some("file") => FileKind::Regular,
                        _ => FileKind::Other,
                    };
                    out.push(FtDirEntry::new(name, kind));
                }
                tracing::debug!(
                    emitted = out.len(),
                    skipped,
                    names = ?out.iter().map(|e| &e.name).collect::<Vec<_>>(),
                    "readdir emitted",
                );
                Ok(out)
            }
            FsReply::Err(e) => {
                // Oracular Dir caps rooted at the bundle entry reject
                // `entries()` with FSERR_BAD_ARG "empty relative path" —
                // same quirk as root-dir stat. Surface an empty listing
                // for the mount root so Finder / ls don't bail; nested
                // dirs still error via NotSupported above.
                tracing::debug!(code = %e.code, msg = %e.message, "readdir fallback → empty");
                Ok(Vec::new())
            }
        }
    }

    fn create(&self, path: &Path, _mode: u32, _flags: i32) -> FtFsResult<u64> {
        trace!(?path, "create");
        let rel = Self::agent_rel(path);
        if rel.is_empty() {
            // Can't create the root — it's the mount source itself.
            return Err(FtFsError::AlreadyExists);
        }
        let snippet = self
            .builder
            .dir_create_file(&self.config.mount_source, &rel);
        self.run_mutating_snippet(snippet)?;
        // libfuse-t-rs's trampoline discards the fh for now; a placeholder
        // zero is fine. Finder follows up with write()s that re-open the
        // file by path.
        Ok(0)
    }

    fn write(&self, path: &Path, offset: u64, data: &[u8], _fh: u64) -> FtFsResult<usize> {
        trace!(?path, offset, size = data.len(), "write");
        let rel = Self::agent_rel(path);
        if rel.is_empty() {
            return Err(FtFsError::IsADirectory);
        }
        let snippet = self
            .builder
            .dir_write_file_at(&self.config.mount_source, &rel, offset, data);
        self.run_mutating_snippet(snippet)?;
        // Optimistic: we don't yet fetch the deploy's `[true, nWritten]`
        // reply from the return channel, so we report the input size.
        // Any admission or propose failure above would have errored out.
        Ok(data.len())
    }

    fn truncate(&self, path: &Path, size: u64) -> FtFsResult<()> {
        trace!(?path, size, "truncate");
        let rel = Self::agent_rel(path);
        if rel.is_empty() {
            return Err(FtFsError::IsADirectory);
        }
        let snippet = self
            .builder
            .dir_truncate_file(&self.config.mount_source, &rel, size);
        self.run_mutating_snippet(snippet)
    }

    fn chmod(&self, path: &Path, mode: u32) -> FtFsResult<()> {
        trace!(?path, mode, "chmod");
        let rel = Self::agent_rel(path);
        if rel.is_empty() {
            // chmod'ing the mount root is a no-op for now — we don't yet
            // expose it in the Fs agent.
            return Err(FtFsError::NotSupported);
        }
        // Agent takes mode as a String (octal spec); format accordingly.
        let mode_str = format!("{:o}", mode & 0o7777);
        let snippet = self
            .builder
            .dir_chmod(&self.config.mount_source, &rel, &mode_str);
        self.run_mutating_snippet(snippet)
    }

    fn unlink(&self, path: &Path) -> FtFsResult<()> {
        trace!(?path, "unlink");
        let rel = Self::agent_rel(path);
        if rel.is_empty() {
            return Err(FtFsError::IsADirectory);
        }
        let snippet = self
            .builder
            .dir_remove_file(&self.config.mount_source, &rel);
        self.run_mutating_snippet(snippet)
    }

    fn rmdir(&self, path: &Path) -> FtFsResult<()> {
        trace!(?path, "rmdir");
        let rel = Self::agent_rel(path);
        if rel.is_empty() {
            return Err(FtFsError::Busy); // can't rmdir the mount root
        }
        let snippet = self
            .builder
            .dir_remove_dir(&self.config.mount_source, &rel, false);
        self.run_mutating_snippet(snippet)
    }

    fn rename(&self, from: &Path, to: &Path) -> FtFsResult<()> {
        trace!(?from, ?to, "rename");
        let from_rel = Self::agent_rel(from);
        let to_rel = Self::agent_rel(to);
        if from_rel.is_empty() || to_rel.is_empty() {
            return Err(FtFsError::InvalidArgument);
        }
        let snippet = self
            .builder
            .dir_rename(&self.config.mount_source, &from_rel, &to_rel);
        self.run_mutating_snippet(snippet)
    }

    fn read(&self, path: &Path, offset: u64, size: usize, _fh: u64) -> FtFsResult<Vec<u8>> {
        trace!(?path, offset, size, "read");
        let rel = Self::agent_rel(path);
        if rel.is_empty() {
            return Err(FtFsError::IsADirectory);
        }
        let snippet =
            self.builder
                .dir_read_file_at(&self.config.mount_source, &rel, offset, size as u64);
        match self.run_readonly_snippet(snippet)? {
            FsReply::Ok { payload } => {
                let bytes = payload.first().and_then(par_as_bytes).unwrap_or(&[]);
                Ok(bytes.to_vec())
            }
            FsReply::Err(e) => Err(fserr_code_to_fs_error(&e.code)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_rel_strips_leading_slash() {
        assert_eq!(F1r3Fs::agent_rel(Path::new("/")), "");
        assert_eq!(F1r3Fs::agent_rel(Path::new("/foo")), "foo");
        assert_eq!(F1r3Fs::agent_rel(Path::new("/foo/bar.txt")), "foo/bar.txt");
    }

    #[test]
    fn ms_to_system_time_sentinel_handling() {
        use std::time::UNIX_EPOCH;
        assert_eq!(ms_to_system_time(None), UNIX_EPOCH);
        assert_eq!(ms_to_system_time(Some(0)), UNIX_EPOCH);
        assert_eq!(ms_to_system_time(Some(-1)), UNIX_EPOCH);
        assert!(ms_to_system_time(Some(1_000)) > UNIX_EPOCH);
    }

    #[test]
    fn fserr_mapping_covers_common_cases() {
        use f1r3drive_rho::*;
        assert_eq!(fserr_code_to_fs_error(FSERR_NOT_FOUND), FtFsError::NotFound);
        assert_eq!(
            fserr_code_to_fs_error(FSERR_PERM),
            FtFsError::PermissionDenied
        );
        assert_eq!(
            fserr_code_to_fs_error(FSERR_UNSUPPORTED),
            FtFsError::NotSupported
        );
        assert_eq!(fserr_code_to_fs_error("FSERR_UNKNOWN_X"), FtFsError::Io);
    }
}
