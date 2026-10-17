//! f1r3drive — FUSE daemon mounting F1r3fly blockchain state.
//!
//! Two mount backends share a single core:
//!
//! - **macOS**: `libfuse_t_rs::mount` drives libfuse-t's high-level
//!   C API; macOS presents the mount via fuse-t's NFSv4 server.
//! - **Linux**: `f1r3drive_fs::mount_linux` drives the kernel's
//!   `/dev/fuse` via `fuser` through our path-indexed adapter.
//!
//! Two mount modes, selected by `--mount-mode`:
//!
//! - `root` (default): mount a single oracular bundle entry as a
//!   file-tree. Driven by `F1r3Fs` talking to the on-chain Fs agent.
//! - `wallets`: mount a synthetic tree of wallet directories with
//!   `.tokens/` subdirs that enumerate the on-chain balance as
//!   `<denom>-REV.<i>.token` bills. Driven by `WalletFs`. See
//!   `docs/architecture/ADR-0001-token-as-file.md`.
//!
//! The CLI surface is shared across modes and platforms except for
//! one platform-only flag: `--volume-name` is macOS-only;
//! `--allow-other` is Linux-only.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use eyre::{bail, Context};
use libfuse_t_rs::Filesystem;

use f1r3drive_client::{KeyPair, NodeClient};
use f1r3drive_fs::{F1r3Fs, FsConfig, WalletFs, WalletFsConfig};
use f1r3drive_wallet::{BalanceCache, RevAddress, WalletRegistry, DEFAULT_TTL};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum MountMode {
    /// Oracular bundle mount. `--mount-source` selects which bundle entry.
    Root,
    /// Synthetic per-wallet tree. Populated by `--track-address` and
    /// `--unlock-key-file`.
    Wallets,
}

#[derive(Debug, Parser)]
#[command(
    name = "f1r3drive",
    version,
    about = "Mount an F1r3fly filesystem via FUSE"
)]
struct Args {
    /// Mount point. Must be an existing empty directory.
    mountpoint: PathBuf,

    /// Validator host to contact over gRPC. Writes submit here.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Validator gRPC port.
    #[arg(long, default_value_t = 40401)]
    port: u16,

    /// Observer host for reads. Defaults to `--host`. Currently only the
    /// validator client is used for both reads and writes; this flag is
    /// accepted for parity with the Java f1r3drive but has no behavioral
    /// effect yet — splitting the clients lands with the Stage 7 work on
    /// consistency semantics.
    #[arg(long)]
    observer_host: Option<String>,

    /// Observer gRPC port. See `--observer-host`.
    #[arg(long)]
    observer_port: Option<u16>,

    /// Deployer address override (hex). Normally derived from the
    /// signing key; accepted for parity with the Java f1r3drive.
    #[arg(long)]
    address: Option<String>,

    /// Top-level filesystem shape. See [`MountMode`].
    #[arg(long, value_enum, default_value_t = MountMode::Root)]
    mount_mode: MountMode,

    /// (`--mount-mode=root` only) Logical name of the bundle entry to
    /// expose as the mount root.
    #[arg(long, default_value = "root")]
    mount_source: String,

    /// Override the on-chain Fs agent URN.
    #[arg(long)]
    fs_urn: Option<String>,

    /// Path to a secp256k1 private-key file (hex or 32 raw bytes). When
    /// absent, the daemon mounts read-only: every write op returns
    /// EACCES. Matches the Java f1r3drive `--key-file` flag. Ignored
    /// in `--mount-mode=wallets`; use `--unlock-key-file` instead.
    #[arg(long, group = "key")]
    key_file: Option<PathBuf>,

    /// secp256k1 private key as a 64-char hex string (with or without
    /// `0x` prefix). Mutually exclusive with `--key-file`.
    #[arg(long, group = "key")]
    private_key: Option<String>,

    /// (`--mount-mode=wallets` only, repeatable) Track a REV address
    /// as `LOCKED-REMOTE-REV-<addr>` so the user can see the wallet
    /// in Finder without having its signing key yet. Call
    /// `UnlockWalletDirectory` via the extension gRPC (Stage 5) to
    /// promote.
    #[arg(long = "track-address")]
    track_addresses: Vec<String>,

    /// (`--mount-mode=wallets` only, repeatable) Load a secp256k1
    /// private key, derive its REV address, and surface the matching
    /// wallet directory as unlocked at startup. Keys load the same
    /// way as `--key-file`.
    #[arg(long = "unlock-key-file")]
    unlock_key_files: Vec<PathBuf>,

    /// (`--mount-mode=wallets` only) Balance-cache TTL. Lower values
    /// mean a `.tokens/` readdir re-queries the chain sooner.
    #[arg(long, value_parser = humantime::parse_duration, default_value = "5s")]
    balance_ttl: Duration,

    /// Shard ID baked into every signed deploy. Must match the node's
    /// configured shard. Default matches local dev shards.
    #[arg(long, default_value = "root")]
    shard_id: String,

    /// Don't auto-propose after writes. The deploy sits in the pool
    /// until a `propose` RPC fires from elsewhere. Mirrors the Java
    /// f1r3drive flag of the same name.
    #[arg(long)]
    manual_propose: bool,

    /// Force read-only mount even if a signing key is available.
    #[arg(long)]
    read_only: bool,

    /// Attribute cache TTL exposed to the kernel (currently informational).
    #[arg(long, value_parser = humantime::parse_duration, default_value = "1s")]
    attr_timeout: Duration,

    /// Entry (lookup) cache TTL exposed to the kernel (currently informational).
    #[arg(long, value_parser = humantime::parse_duration, default_value = "1s")]
    entry_timeout: Duration,

    /// Finder volume name (macOS only; ignored on Linux).
    #[arg(long, default_value = "f1r3drive")]
    volume_name: String,

    /// `-o allow_other` on the Linux mount, letting non-owning users
    /// see the mount. Requires `user_allow_other` in `/etc/fuse.conf`
    /// on most distros. Ignored on macOS.
    #[arg(long)]
    allow_other: bool,

    /// Enable verbose tracing.
    #[arg(long)]
    debug: bool,
}

fn load_signer(args: &Args) -> eyre::Result<Option<KeyPair>> {
    match (args.key_file.as_ref(), args.private_key.as_ref()) {
        (Some(path), None) => Ok(Some(
            KeyPair::from_file(path).wrap_err_with(|| format!("loading key from {path:?}"))?,
        )),
        (None, Some(hex)) => Ok(Some(
            KeyPair::from_private_hex(hex).wrap_err("parsing --private-key")?,
        )),
        (None, None) => Ok(None),
        (Some(_), Some(_)) => bail!("--key-file and --private-key are mutually exclusive"),
    }
}

/// Build the wallet registry from `--track-address` + `--unlock-key-file`.
/// Errors on malformed addresses or unreadable keyfiles so the daemon
/// surfaces configuration mistakes at startup rather than at access
/// time.
fn build_wallet_registry(args: &Args) -> eyre::Result<Arc<WalletRegistry>> {
    let registry = Arc::new(WalletRegistry::new());

    for raw in &args.track_addresses {
        let addr = RevAddress::parse(raw).wrap_err_with(|| format!("--track-address {raw:?}"))?;
        registry.track(addr);
    }

    for path in &args.unlock_key_files {
        let kp = KeyPair::from_file(path)
            .wrap_err_with(|| format!("--unlock-key-file {}", path.display()))?;
        let addr =
            RevAddress::from_public_key_bytes(kp.public_key_bytes()).wrap_err_with(|| {
                format!(
                    "deriving REV address from --unlock-key-file {}",
                    path.display()
                )
            })?;
        registry.unlock(addr);
    }

    Ok(registry)
}

fn main() -> eyre::Result<()> {
    let args = Args::parse();

    let level = if args.debug { "trace" } else { "info" };
    // Log to stderr. Daemon stdout is often null-piped by whatever
    // supervisor spawned us (test fixture, systemd, launchd); stderr
    // conventionally carries diagnostics on Unix.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(tracing_subscriber::EnvFilter::new(format!(
            "f1r3drive={level},f1r3drive_fs={level},f1r3drive_client={level},f1r3drive_rho={level},f1r3drive_wallet={level},libfuse_t_rs={level}"
        )))
        .init();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .wrap_err("failed to start tokio runtime")?;

    let client = runtime
        .block_on(NodeClient::connect(&args.host, args.port))
        .wrap_err_with(|| format!("failed to connect to {}:{}", args.host, args.port))?;

    match args.mount_mode {
        MountMode::Root => mount_root_mode(&args, &runtime, client),
        MountMode::Wallets => mount_wallets_mode(&args, &runtime, client),
    }
}

fn mount_root_mode(
    args: &Args,
    runtime: &tokio::runtime::Runtime,
    client: NodeClient,
) -> eyre::Result<()> {
    let signer = load_signer(args)?;
    let effective_read_only = args.read_only || signer.is_none();

    let config = FsConfig {
        mount_source: args.mount_source.clone(),
        fs_urn_override: args.fs_urn.clone(),
        attr_ttl: args.attr_timeout,
        entry_ttl: args.entry_timeout,
        signer,
        shard_id: args.shard_id.clone(),
        manual_propose: args.manual_propose,
        ..FsConfig::default()
    };

    tracing::info!(
        mountpoint = %args.mountpoint.display(),
        mount_source = %config.mount_source,
        read_only = effective_read_only,
        manual_propose = config.manual_propose,
        "mounting (root mode)",
    );

    let fs = F1r3Fs::new(runtime.handle().clone(), client, config);
    mount_fs(fs, args, effective_read_only)
}

fn mount_wallets_mode(
    args: &Args,
    runtime: &tokio::runtime::Runtime,
    client: NodeClient,
) -> eyre::Result<()> {
    if args.key_file.is_some() || args.private_key.is_some() {
        tracing::warn!(
            "--key-file / --private-key are ignored in --mount-mode=wallets; \
             use --unlock-key-file to pre-unlock a wallet directory",
        );
    }

    let registry = build_wallet_registry(args)?;
    if registry.is_empty() {
        tracing::warn!(
            "no wallets tracked at startup — pass --track-address / --unlock-key-file \
             or call UnlockWalletDirectory via the Finder extension gRPC (Stage 5)",
        );
    }
    let cache = Arc::new(BalanceCache::with_ttl(args.balance_ttl));

    tracing::info!(
        mountpoint = %args.mountpoint.display(),
        tracked = registry.len(),
        balance_ttl = ?args.balance_ttl,
        default_ttl = ?DEFAULT_TTL,
        "mounting (wallets mode)",
    );

    let fs = WalletFs::new(
        runtime.handle().clone(),
        client,
        registry,
        cache,
        WalletFsConfig::default(),
    );
    // Transfers aren't implemented until Stage 4; v1 is read-only.
    mount_fs(fs, args, true)
}

/// Platform-dispatched mount. The caller's `fs` is any
/// `Filesystem` impl — both `F1r3Fs` and `WalletFs` qualify. The
/// `read_only` flag toggles the kernel-side RO guard; the mount
/// options are otherwise shared.
fn mount_fs<F>(fs: F, args: &Args, read_only: bool) -> eyre::Result<()>
where
    F: Filesystem + Send + Sync + 'static,
{
    let mountpoint: &Path = args.mountpoint.as_ref();

    #[cfg(target_os = "macos")]
    {
        let mount_opts = libfuse_t_rs::MountOptions {
            fs_name: Some("f1r3drive".to_string()),
            volume_name: Some(args.volume_name.clone()),
            read_only,
            // `local` tells macOS to treat this NFS mount as a local
            // filesystem rather than a network volume — bypasses the
            // "Network Volumes" TCC gate that otherwise blocks writes
            // from any process (including Terminal) that lacks the
            // Full Disk Access-adjacent "Network Volumes" permission.
            // Side-effects: Spotlight indexes it; it shows up next to
            // other local volumes in Finder sidebar.
            extra: vec!["local".to_string()],
        };

        libfuse_t_rs::mount(fs, mountpoint, &mount_opts)
            .wrap_err_with(|| format!("mount at {} failed", mountpoint.display()))?;
    }

    #[cfg(target_os = "linux")]
    {
        let opts = f1r3drive_fs::LinuxMountOptions {
            fs_name: Some("f1r3drive".to_string()),
            read_only,
            allow_other: args.allow_other,
            extra: Vec::new(),
        };

        f1r3drive_fs::mount_linux(fs, mountpoint, &opts)
            .map_err(eyre::Report::from)
            .wrap_err_with(|| format!("mount at {} failed", mountpoint.display()))?;
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (fs, read_only, args);
        eyre::bail!("f1r3drive supports macOS (fuse-t) and Linux (fuser) only");
    }

    Ok(())
}
