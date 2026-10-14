//! Daemon configuration shared across FUSE handlers.

use std::time::Duration;

use f1r3drive_client::KeyPair;

/// Immutable per-mount configuration passed into the FUSE filesystem.
pub struct FsConfig {
    /// The logical name of the bundle entry that serves as the mount
    /// root. The on-chain `Fs` agent indexes files by logical name, not
    /// absolute path; this picks which bundle entry we expose.
    pub mount_source: String,

    /// Owner uid reported in `getattr` replies. Normally the invoking
    /// user; the on-chain stat record doesn't carry a POSIX uid in
    /// consensus mode so this is a client-side display choice.
    pub display_uid: u32,

    /// Owner gid reported in `getattr`.
    pub display_gid: u32,

    /// How long the kernel is allowed to cache `getattr` results
    /// (currently informational — the TTL isn't yet threaded into libfuse).
    pub attr_ttl: Duration,

    /// How long the kernel is allowed to cache `lookup` results.
    pub entry_ttl: Duration,

    /// Override the Fs agent URN. `None` → use the genesis-published URN.
    pub fs_urn_override: Option<String>,

    /// secp256k1 keypair used to sign write deploys. `None` → the daemon
    /// is read-only; every mutator op returns `PermissionDenied`.
    pub signer: Option<KeyPair>,

    /// Shard ID baked into every deploy. Must match the node's config.
    pub shard_id: String,

    /// If true, don't auto-propose after each write. The deploy sits in
    /// the pool until the operator calls `propose` manually (matches the
    /// Java f1r3drive `--manual-propose` flag).
    pub manual_propose: bool,
}

impl std::fmt::Debug for FsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsConfig")
            .field("mount_source", &self.mount_source)
            .field("display_uid", &self.display_uid)
            .field("display_gid", &self.display_gid)
            .field("attr_ttl", &self.attr_ttl)
            .field("entry_ttl", &self.entry_ttl)
            .field("fs_urn_override", &self.fs_urn_override)
            .field("signer", &self.signer.as_ref().map(|_| "<secp256k1>"))
            .field("shard_id", &self.shard_id)
            .field("manual_propose", &self.manual_propose)
            .finish()
    }
}

impl Default for FsConfig {
    fn default() -> Self {
        Self {
            mount_source: "root".to_string(),
            display_uid: unsafe { libc::getuid() },
            display_gid: unsafe { libc::getgid() },
            attr_ttl: Duration::from_secs(1),
            entry_ttl: Duration::from_secs(1),
            fs_urn_override: None,
            signer: None,
            shard_id: "root".to_string(),
            manual_propose: false,
        }
    }
}
