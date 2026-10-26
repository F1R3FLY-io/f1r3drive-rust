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

use f1r3drive_client::{KeyPair, NodeClient};
use f1r3drive_crypto::Keystore;
use f1r3drive_ext::{
    forward_unlock, ExtensionService, UnlockLink, UnlockOutcome, DEFAULT_EXT_HOST, DEFAULT_EXT_PORT,
};
use f1r3drive_fs::{
    BillPresenter, BlobStore, ChainBlobStore, ContractRegistry, ExtensionFs, ExtensionFsConfig,
    F1r3Fs, Filesystem, FsConfig, InMemoryBlobStore, KeyStore, ListingStore, SidecarBlobStore,
    WalletFs, WalletFsConfig,
};
use f1r3drive_identity::Identity;
use f1r3drive_wallet::{BalanceCache, RevAddress, WalletRegistry, DEFAULT_TTL};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum MountMode {
    /// Oracular bundle mount. `--mount-source` selects which bundle entry.
    Root,
    /// Synthetic per-wallet tree. Populated by `--track-address` and
    /// `--unlock-key-file`.
    Wallets,
    /// Encrypted per-pubkey folders + contract-folder plug-ins
    /// (ADR-0002). Identity bootstrapped from `--state-dir`.
    Extension,
}

#[derive(Debug, Parser)]
#[command(
    name = "f1r3drive",
    version,
    about = "Mount an F1r3fly filesystem via FUSE"
)]
struct Args {
    /// Mount point. Must be an existing empty directory. Not required
    /// when running in `--open-url` one-shot mode.
    mountpoint: Option<PathBuf>,

    /// One-shot CLI mode: parse an `f1r3drive://unlock?...` URL and
    /// forward it to an already-running daemon's extension gRPC
    /// endpoint. Prints the daemon's reply and exits. The macOS app
    /// bundle (Stage 7) registers this URL scheme in Info.plist and
    /// shells out here for the actual work.
    #[arg(long)]
    open_url: Option<String>,

    /// Validator host to contact over gRPC. Writes submit here.
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// Validator gRPC port.
    #[arg(long, default_value_t = 40401)]
    port: u16,

    /// Observer host for reads. When set together with `--observer-port`,
    /// `exploratory_deploy` / `get_data_at_name` / `is_finalized` route
    /// to this endpoint instead of the validator at `--host`. Writes
    /// (deploy + propose) continue to go to the validator. Production
    /// shards reject `exploratory_deploy` on validators
    /// (`is_read_only || dev_mode` in casper), so pointing a client
    /// at the read-only observer is the usual configuration.
    #[arg(long, requires = "observer_port")]
    observer_host: Option<String>,

    /// Observer gRPC deploy-service port. See `--observer-host`.
    #[arg(long, requires = "observer_host")]
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

    /// (`--mount-mode=wallets` only) Loopback TCP port the Finder
    /// Sync extension gRPC listens on. Defaults to the external
    /// deploy port + 10 (40411), mirroring Java f1r3drive. Set to 0
    /// to disable the extension server entirely (headless use).
    #[arg(long, default_value_t = DEFAULT_EXT_PORT)]
    extension_grpc_port: u16,

    /// (`--mount-mode=extension` only) Where to keep the user's local
    /// identity + per-blob key store. Defaults to `$HOME/.f1r3drive`.
    /// Created with 0700 perms on first run.
    #[arg(long)]
    state_dir: Option<PathBuf>,

    /// (`--mount-mode=extension` only, repeatable) Render this
    /// pubkey-folder in `readdir /` even though we don't own it.
    /// Readdir on the folder itself still returns empty — the ACL
    /// is per-folder, not per-root-listing.
    #[arg(long = "track-pubkey")]
    track_pubkeys: Vec<String>,

    /// (`--mount-mode=extension` only) Persist encrypted blobs
    /// on-chain via the Fs agent instead of the default in-process
    /// store. Requires `--key-file` / `--private-key` for signing
    /// put/delete deploys. The target bundle dir is set by
    /// `--mount-source` (defaults to `root`) and must already be
    /// provisioned on the shard.
    #[arg(long)]
    chain_blobs: bool,

    /// (`--mount-mode=extension` only, requires `--chain-blobs`) Base
    /// URL of the per-node `file-read-service` HTTP sidecar
    /// (`scripts/file-read-service` in f1r3node-rust). When set, blob
    /// `get` requests go through the sidecar's loopback HTTP endpoint
    /// (reads from WAL-replicated local disk, ~1 ms) and fall back
    /// to the signed-deploy chain path on a 5xx / connect-refused /
    /// timeout. Writes always go via the chain. Example:
    /// `http://127.0.0.1:9411`.
    #[arg(long)]
    sidecar_url: Option<String>,

    /// (`--mount-mode=extension` only) Route paid-transfer mint /
    /// rmdir / purchase deploys through the on-chain Rholang factory.
    /// Requires `--key-file` / `--private-key`. Without this flag,
    /// drops into `/<me>/Paid transfer/` store a SELF envelope
    /// locally (slice-8 behavior) and token-drop renames return
    /// `NotSupported` — on-chain settlement is opt-in.
    #[arg(long)]
    chain_factory: bool,

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

/// Build the wallet registry + keystore from `--track-address` +
/// `--unlock-key-file`. Errors on malformed addresses or unreadable
/// keyfiles so the daemon surfaces configuration mistakes at
/// startup rather than at access time.
fn build_wallet_state(args: &Args) -> eyre::Result<(Arc<WalletRegistry>, Arc<KeyStore>)> {
    let registry = Arc::new(WalletRegistry::new());
    let keys = Arc::new(KeyStore::new());

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
        registry.unlock(addr.clone());
        keys.insert(addr, kp);
    }

    Ok((registry, keys))
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

    // One-shot deep-link mode. Does NOT touch the mountpoint or
    // the node — it forwards to a *separate*, already-running
    // daemon on loopback.
    if let Some(url) = &args.open_url {
        return runtime.block_on(run_open_url(url, args.extension_grpc_port));
    }

    let mountpoint = args
        .mountpoint
        .clone()
        .ok_or_else(|| eyre::eyre!("mountpoint is required unless --open-url is set"))?;

    let client = {
        let base = runtime
            .block_on(NodeClient::connect(&args.host, args.port))
            .wrap_err_with(|| format!("failed to connect to {}:{}", args.host, args.port))?;
        match (args.observer_host.as_deref(), args.observer_port) {
            (Some(obs_host), Some(obs_port)) => {
                tracing::info!(
                    observer_host = obs_host,
                    observer_port = obs_port,
                    "routing exploratory_deploy / get_data_at_name / is_finalized via observer"
                );
                runtime
                    .block_on(base.with_observer(obs_host, obs_port))
                    .wrap_err_with(|| {
                        format!("failed to connect to observer {obs_host}:{obs_port}")
                    })?
            }
            (None, None) => base,
            _ => eyre::bail!(
                "--observer-host and --observer-port must be set together (got one but not the other)"
            ),
        }
    };

    match args.mount_mode {
        MountMode::Root => mount_root_mode(&args, &mountpoint, &runtime, client),
        MountMode::Wallets => mount_wallets_mode(&args, &mountpoint, &runtime, client),
        MountMode::Extension => mount_extension_mode(&args, &mountpoint, &runtime, client),
    }
}

async fn run_open_url(url: &str, port: u16) -> eyre::Result<()> {
    let link = UnlockLink::parse(url).wrap_err("parse --open-url")?;
    tracing::info!(rev_address = %link.rev_address, port, "forwarding unlock via extension gRPC");
    match forward_unlock(link, DEFAULT_EXT_HOST, port).await {
        UnlockOutcome::Success => {
            println!("unlock: ok");
            Ok(())
        }
        UnlockOutcome::DaemonError(msg) => eyre::bail!("daemon rejected unlock: {msg}"),
        UnlockOutcome::Transport(e) => Err(e).wrap_err("transport"),
        UnlockOutcome::Rpc(s) => eyre::bail!("gRPC: {s}"),
    }
}

fn mount_root_mode(
    args: &Args,
    mountpoint: &Path,
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
        mountpoint = %mountpoint.display(),
        mount_source = %config.mount_source,
        read_only = effective_read_only,
        manual_propose = config.manual_propose,
        "mounting (root mode)",
    );

    let fs = F1r3Fs::new(runtime.handle().clone(), client, config);
    mount_fs(fs, args, mountpoint, effective_read_only)
}

fn mount_wallets_mode(
    args: &Args,
    mountpoint: &Path,
    runtime: &tokio::runtime::Runtime,
    client: NodeClient,
) -> eyre::Result<()> {
    if args.key_file.is_some() || args.private_key.is_some() {
        tracing::warn!(
            "--key-file / --private-key are ignored in --mount-mode=wallets; \
             use --unlock-key-file to pre-unlock a wallet directory",
        );
    }

    let (registry, keys) = build_wallet_state(args)?;
    if registry.is_empty() {
        tracing::warn!(
            "no wallets tracked at startup — pass --track-address / --unlock-key-file \
             or call UnlockWalletDirectory via the Finder extension gRPC",
        );
    }
    let cache = Arc::new(BalanceCache::with_ttl(args.balance_ttl));
    let presenter = Arc::new(BillPresenter::new());

    tracing::info!(
        mountpoint = %mountpoint.display(),
        tracked = registry.len(),
        balance_ttl = ?args.balance_ttl,
        default_ttl = ?DEFAULT_TTL,
        "mounting (wallets mode)",
    );

    // Finder-extension gRPC server. We need a second NodeClient
    // (tonic's Channel is Arc-backed, but our wrapper owns its own
    // mutex-serialized state). Clone the connection params and
    // establish a fresh client for the ext server.
    if args.extension_grpc_port != 0 {
        let ext_client = {
            let base = runtime
                .block_on(NodeClient::connect(&args.host, args.port))
                .wrap_err_with(|| {
                    format!(
                        "ext-server failed to connect to {}:{}",
                        args.host, args.port
                    )
                })?;
            match (args.observer_host.as_deref(), args.observer_port) {
                (Some(obs_host), Some(obs_port)) => runtime
                    .block_on(base.with_observer(obs_host, obs_port))
                    .wrap_err_with(|| {
                        format!("ext-server failed to connect to observer {obs_host}:{obs_port}")
                    })?,
                _ => base,
            }
        };
        let addr: std::net::SocketAddr = format!("{DEFAULT_EXT_HOST}:{}", args.extension_grpc_port)
            .parse()
            .wrap_err("parse extension-grpc endpoint")?;
        let svc = ExtensionService::new(
            ext_client,
            Arc::clone(&registry),
            Arc::clone(&cache),
            Arc::clone(&keys),
            Arc::clone(&presenter),
            mountpoint.to_path_buf(),
        );
        let _handle = {
            let _enter = runtime.enter();
            f1r3drive_ext::serve(svc, addr)
        };
        tracing::info!(%addr, "finder-ext gRPC server spawned");
    } else {
        tracing::info!("extension-grpc-port=0 → Finder extension gRPC server disabled");
    }

    let fs_config = WalletFsConfig {
        shard_id: args.shard_id.clone(),
        manual_propose: args.manual_propose,
        ..WalletFsConfig::default()
    };

    let fs = WalletFs::new(
        runtime.handle().clone(),
        client,
        registry,
        cache,
        keys,
        presenter,
        fs_config,
    );
    // Transfers are now wired, but the mount itself is still
    // read-only from the kernel's view — the only "writes" we
    // accept go through op_rename on *.token files, which
    // libfuse-t forwards even on a read-only mount since rename
    // is a directory op. Leave the RO flag on for safety.
    mount_fs(fs, args, mountpoint, true)
}

/// `--mount-mode=extension` — ADR-0002 encrypted-content mount. The
/// blob store is selected by `--chain-blobs`: default is the
/// in-process `InMemoryBlobStore` (local dev / tests, no node
/// deploys); `--chain-blobs` swaps in `ChainBlobStore`, which signs
/// and submits deploys against the Fs agent.
fn mount_extension_mode(
    args: &Args,
    mountpoint: &Path,
    runtime: &tokio::runtime::Runtime,
    client: NodeClient,
) -> eyre::Result<()> {
    let state_dir = args.state_dir.clone().unwrap_or_else(|| {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".f1r3drive")
    });
    let identity = Identity::load_or_create(&state_dir)
        .wrap_err_with(|| format!("bootstrap identity at {}", state_dir.display()))?;
    let keystore = Keystore::open(&state_dir)
        .wrap_err_with(|| format!("open keystore at {}", state_dir.display()))?;

    let signer_opt = load_signer(args)?;

    let blobs: Arc<dyn BlobStore> = if args.chain_blobs {
        let signer = signer_opt.clone().ok_or_else(|| {
            eyre::eyre!(
                "--chain-blobs requires a signing key (--key-file or --private-key); \
                 the Fs-agent-backed blob store signs every put / delete deploy"
            )
        })?;
        tracing::info!(
            bundle_dir = %args.mount_source,
            shard_id = %args.shard_id,
            manual_propose = args.manual_propose,
            sidecar_url = ?args.sidecar_url,
            "extension mode: using on-chain Fs-agent blob store",
        );
        let chain: Arc<dyn BlobStore> = Arc::new(ChainBlobStore::new(
            runtime.handle().clone(),
            client.clone(),
            signer,
            args.shard_id.clone(),
            args.manual_propose,
            args.mount_source.clone(),
            args.fs_urn.clone(),
        ));
        match args.sidecar_url.as_deref() {
            Some(url) => {
                tracing::info!(
                    sidecar_url = url,
                    bundle_dir = %args.mount_source,
                    "wrapping ChainBlobStore in SidecarBlobStore — reads go via HTTP, writes via gRPC",
                );
                Arc::new(SidecarBlobStore::new(
                    url.to_string(),
                    args.mount_source.clone(),
                    chain,
                ))
            }
            None => chain,
        }
    } else {
        if args.sidecar_url.is_some() {
            eyre::bail!(
                "--sidecar-url requires --chain-blobs (the sidecar reads the same bundle \
                 the chain store writes to)"
            );
        }
        tracing::info!("extension mode: using in-process InMemoryBlobStore (set --chain-blobs for on-chain persistence)");
        Arc::new(InMemoryBlobStore::new())
    };

    let factory = if args.chain_factory {
        let signer = signer_opt.clone().ok_or_else(|| {
            eyre::eyre!(
                "--chain-factory requires a signing key (--key-file or --private-key); \
                 mint / rmdir / purchase deploys are all signed"
            )
        })?;
        tracing::info!(
            shard_id = %args.shard_id,
            manual_propose = args.manual_propose,
            "extension mode: on-chain paid-transfer factory enabled",
        );
        Some(Arc::new(f1r3drive_fs::FactoryClient::new(
            runtime.handle().clone(),
            client.clone(),
            signer,
            args.shard_id.clone(),
            args.manual_propose,
        )))
    } else {
        None
    };

    // Disk-backed ListingStore so Alice's minted listings survive
    // daemon restarts.
    let listings = Arc::new(
        ListingStore::open(&state_dir)
            .wrap_err_with(|| format!("open listing store at {}", state_dir.display()))?,
    );

    tracing::info!(
        mountpoint = %mountpoint.display(),
        state_dir = %state_dir.display(),
        pubkey = %identity.pubkey_hex(),
        tracked = args.track_pubkeys.len(),
        chain_blobs = args.chain_blobs,
        listings_loaded = listings.len(),
        "mounting (extension mode)",
    );

    // Derive owner_rev from the SIGNING key, not the identity key.
    // The Rholang vault's authKey is keyed on the signer's REV, so
    // mint/release/sweep deploys all have to address a vault at
    // the signer-derived REV — identity-derived REV would have no
    // associated vault and the vault's authKey check would reject
    // every transfer with FSERR_TRANSFER_FAILED: Invalid AuthKey.
    let owner_rev = match signer_opt.as_ref() {
        Some(signer) => RevAddress::from_public_key_bytes(signer.public_key_bytes())
            .wrap_err("derive owner REV address from signing key")?
            .to_base58(),
        None => {
            // No signer → factory + chain-blobs are both disabled
            // (we errored earlier in those branches), so `owner_rev`
            // is only used for display + manifest publication.
            // Fall back to the identity-derived REV so logs stay
            // populated.
            RevAddress::from_public_key_bytes(identity.public_key_bytes())
                .wrap_err("derive owner REV address from identity key")?
                .to_base58()
        }
    };
    let identity_arc = Arc::new(identity);
    let fs = ExtensionFs::with_registry(
        identity_arc.clone(),
        args.track_pubkeys.clone(),
        ExtensionFsConfig::default(),
        blobs,
        Arc::new(keystore),
        Arc::new(ContractRegistry::new()),
        listings,
    );
    let fs = if let Some(factory) = factory {
        fs.with_factory(factory, owner_rev)
    } else {
        fs
    };
    // Attach balance plumbing so `.tokens/` renders the owner's real
    // bill decomposition and the purchase path can refuse drops that
    // don't cover the listing price. `BalanceCache` matches wallet-
    // mode semantics (shared 5s TTL default); `NodeClient` is cloned
    // because `ChainBlobStore` + `FactoryClient` also hold their own
    // handles — tonic channels are Arc-backed, so this is cheap.
    let balance_cache = Arc::new(BalanceCache::with_ttl(args.balance_ttl));
    let fs = fs.with_balance_source(balance_cache, client, runtime.handle().clone());
    // Extension mode supports writes (create/write/unlink/rename/rmdir
    // through ExtensionFs). The kernel-level read-only flag was a
    // leftover from the slice-3 skeleton; honour --read-only only
    // when the user explicitly opts in.
    mount_fs(fs, args, mountpoint, args.read_only)
}

/// Platform-dispatched mount. The caller's `fs` is any
/// `Filesystem` impl — both `F1r3Fs` and `WalletFs` qualify. The
/// `read_only` flag toggles the kernel-side RO guard; the mount
/// options are otherwise shared.
fn mount_fs<F>(fs: F, args: &Args, mountpoint: &Path, read_only: bool) -> eyre::Result<()>
where
    F: Filesystem + Send + Sync + 'static,
{
    #[cfg(target_os = "macos")]
    {
        let mount_opts = libfuse_t_rs::MountOptions {
            fs_name: Some("f1r3drive".to_string()),
            volume_name: Some(args.volume_name.clone()),
            read_only,
            // Darwin NFS tuning (fuse-t presents our mount as NFSv4):
            //
            // - `local`: classify as local-not-network, so Finder
            //   groups the mount with real local volumes and Spotlight
            //   can index it. Does not actually bypass the Network
            //   Volumes / Full Disk Access TCC gates on macOS 14+.
            // - `noappledouble`: suppress the `._<file>` AppleDouble
            //   sidecars Finder would otherwise write to track
            //   xattr-style metadata we don't natively support.
            // - `noapplexattr`: stop advertising xattr fallbacks that
            //   also funnel into the AppleDouble path.
            // - `nolocalcaches`: skip the client-side NFS attr/data
            //   caches — writes land immediately rather than through
            //   a write-back buffer, matching the "the shard is the
            //   source of truth" invariant.
            extra: vec![
                "local".to_string(),
                "noappledouble".to_string(),
                "noapplexattr".to_string(),
                "nolocalcaches".to_string(),
            ],
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
