//! `F1r3Fs` — the FUSE filesystem that mounts F1r3fly blockchain state.
//!
//! Two mount backends share a single `F1r3Fs` body of behavior:
//!
//! - **macOS**: `libfuse-t-rs` drives libfuse-t's high-level C API,
//!   bridging to the kernel via fuse-t's NFSv4 server.
//! - **Linux**: `fuser` drives `/dev/fuse` directly. The adapter
//!   lives in [`linux_mount`] and translates fuser's inode-based
//!   callbacks into our path-based `Filesystem` trait via a monotonic
//!   `inode ↔ path` registry.
//!
//! The shared body of behavior (`F1r3Fs` + the `Filesystem` trait
//! impl) is backend-agnostic. Each backend owns its own `mount`
//! function.

pub mod bill_presenter;
pub mod blob_store;
pub mod chain_blob_store;
pub mod config;
pub mod extension_fs;
pub mod fs;
pub mod wallet_fs;

#[cfg(target_os = "linux")]
pub mod linux_mount;

pub use bill_presenter::{BillPresenter, ChangeError};
pub use blob_store::{BlobError, BlobResult, BlobStore, InMemoryBlobStore};
pub use chain_blob_store::ChainBlobStore;
pub use config::FsConfig;
pub use extension_fs::{
    ExtPath, ExtensionFs, ExtensionFsConfig, PAID_TRANSFER_DIR, PUBKEY_HEX_LEN,
};
pub use fs::F1r3Fs;
pub use wallet_fs::{KeyStore, WalletFs, WalletFsConfig, WalletPath, LOCKED_PREFIX, TOKENS_DIR};

/// Re-export the shared `Filesystem` trait. `libfuse-t-rs` is a
/// cross-platform dep (the trait + attribute types live there even
/// though the mount pipeline is macOS-only), so consumers that need
/// the trait but don't want to add their own `libfuse-t-rs`
/// dependency go through here.
pub use libfuse_t_rs::Filesystem;

#[cfg(target_os = "linux")]
pub use linux_mount::{mount as mount_linux, LinuxMountOptions};
