//! `F1r3Fs` — the FUSE filesystem that mounts F1r3fly blockchain state.
//!
//! On macOS, built on top of `libfuse-t-rs` (which drives libfuse-t's
//! high-level C API). Linux support follows a different path (fuser
//! against `/dev/fuse`) and is out of scope for v1.

#![cfg(target_os = "macos")]

pub mod config;
pub mod fs;

pub use config::FsConfig;
pub use fs::F1r3Fs;
