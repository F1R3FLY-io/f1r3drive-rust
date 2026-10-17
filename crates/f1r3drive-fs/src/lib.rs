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

pub mod config;
pub mod fs;
pub mod wallet_fs;

#[cfg(target_os = "linux")]
pub mod linux_mount;

pub use config::FsConfig;
pub use fs::F1r3Fs;
pub use wallet_fs::{WalletFs, WalletFsConfig, WalletPath, LOCKED_PREFIX, TOKENS_DIR};

#[cfg(target_os = "linux")]
pub use linux_mount::{mount as mount_linux, LinuxMountOptions};
