//! f1r3drive — FUSE daemon mounting F1r3fly blockchain state.
//!
//! On macOS this runs on libfuse-t via the `libfuse-t-rs` safe wrapper.
//! Linux support is deferred (fuser's `/dev/fuse` path works there but
//! the integration isn't wired yet).

#![cfg(target_os = "macos")]

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use eyre::{bail, Context};

use f1r3drive_client::{KeyPair, NodeClient};
use f1r3drive_fs::{F1r3Fs, FsConfig};
use libfuse_t_rs::MountOptions;

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

    /// Logical name of the bundle entry to expose as the mount root.
    #[arg(long, default_value = "root")]
    mount_source: String,

    /// Override the on-chain Fs agent URN.
    #[arg(long)]
    fs_urn: Option<String>,

    /// Path to a secp256k1 private-key file (hex or 32 raw bytes). When
    /// absent, the daemon mounts read-only: every write op returns
    /// EACCES. Matches the Java f1r3drive `--key-file` flag.
    #[arg(long, group = "key")]
    key_file: Option<PathBuf>,

    /// secp256k1 private key as a 64-char hex string (with or without
    /// `0x` prefix). Mutually exclusive with `--key-file`.
    #[arg(long, group = "key")]
    private_key: Option<String>,

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

    /// Finder volume name (macOS).
    #[arg(long, default_value = "f1r3drive")]
    volume_name: String,

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

fn main() -> eyre::Result<()> {
    let args = Args::parse();

    let level = if args.debug { "trace" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(format!(
            "f1r3drive={level},f1r3drive_fs={level},f1r3drive_client={level},f1r3drive_rho={level},libfuse_t_rs={level}"
        )))
        .init();

    let signer = load_signer(&args)?;
    let effective_read_only = args.read_only || signer.is_none();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .wrap_err("failed to start tokio runtime")?;

    let client = runtime
        .block_on(NodeClient::connect(&args.host, args.port))
        .wrap_err_with(|| format!("failed to connect to {}:{}", args.host, args.port))?;

    let config = FsConfig {
        mount_source: args.mount_source,
        fs_urn_override: args.fs_urn,
        attr_ttl: args.attr_timeout,
        entry_ttl: args.entry_timeout,
        signer,
        shard_id: args.shard_id,
        manual_propose: args.manual_propose,
        ..FsConfig::default()
    };

    tracing::info!(
        mountpoint = %args.mountpoint.display(),
        mount_source = %config.mount_source,
        read_only = effective_read_only,
        manual_propose = config.manual_propose,
        "mounting",
    );

    let fs = F1r3Fs::new(runtime.handle().clone(), client, config);

    let mount_opts = MountOptions {
        fs_name: Some("f1r3drive".to_string()),
        volume_name: Some(args.volume_name),
        read_only: effective_read_only,
        // `local` tells macOS to treat this NFS mount as a local
        // filesystem rather than a network volume — bypasses the
        // "Network Volumes" TCC gate that otherwise blocks writes
        // from any process (including Terminal) that lacks the
        // Full Disk Access-adjacent "Network Volumes" permission.
        // Side-effects: Spotlight indexes it; it shows up next to
        // other local volumes in Finder sidebar.
        extra: vec!["local".to_string()],
    };

    libfuse_t_rs::mount(fs, &args.mountpoint, &mount_opts)
        .wrap_err_with(|| format!("mount at {} failed", args.mountpoint.display()))?;

    Ok(())
}
