//! Safe Rust wrapper over libfuse-t's high-level C API.
//!
//! Implement [`Filesystem`] with path-oriented operations, then call
//! [`mount`] or [`spawn_mount`] to run it. The crate takes care of
//! trampolining C callbacks into trait method calls, panic isolation,
//! and session teardown.
//!
//! # Platform
//!
//! macOS only. On Linux this crate compiles to an empty library — a
//! downstream daemon targeting Linux should pick a different mount
//! implementation (`fuser` works on Linux via `/dev/fuse`).
//!
//! # Prerequisites
//!
//! `brew install --cask fuse-t`.
//!
//! # Why not `fuser`?
//!
//! `fuser` speaks the Linux `/dev/fuse` kernel protocol. `fuse-t` has
//! no kernel component and only exposes libfuse's high-level C API,
//! so the two are architecturally incompatible — see the sibling
//! `libfuse-t-sys` crate's docs for the full story.

// The `Filesystem` trait, attribute types, and error enum are
// cross-platform — the FUSE layer only matters at the mount step.
// We un-gate those modules so the trait is usable from a Linux
// `fuser`-based backend as well. The actual libfuse-t mount
// (`mount` / `spawn_mount` / trampolines) stays macOS-only.

pub mod attr;
pub mod error;
pub mod fs;

pub use attr::{DirEntry, FileAttr, FileKind};
pub use error::{FsError, FsResult};
pub use fs::{Filesystem, StatVfs};

#[cfg(target_os = "macos")]
mod mount;
#[cfg(target_os = "macos")]
mod trampolines;
#[cfg(target_os = "macos")]
pub use mount::{mount, spawn_mount, BackgroundSession, MountOptions};
