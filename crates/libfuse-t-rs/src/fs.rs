//! The `Filesystem` trait callers implement.
//!
//! All methods are `&self`; interior mutability is the caller's problem.
//! libfuse-t drives these from a thread pool via `fuse_loop_mt`, so each
//! method must be `Send + Sync`.

use std::path::Path;

use crate::attr::{DirEntry, FileAttr};
use crate::error::{FsError, FsResult};

/// A FUSE filesystem backend.
///
/// Default implementations return [`FsError::NotSupported`] where
/// applicable, so a read-only filesystem can implement just `getattr`,
/// `readdir`, `read`, and `open`.
pub trait Filesystem: Send + Sync + 'static {
    /// Called once when libfuse-t's init handshake completes. Default is
    /// no-op.
    fn init(&self) {}

    /// Called once at shutdown.
    fn destroy(&self) {}

    /// Return attributes of the entry at `path`.
    fn getattr(&self, path: &Path) -> FsResult<FileAttr>;

    /// Open a file at `path`. Return a filesystem-chosen opaque handle
    /// which will be passed back to [`Filesystem::read`] / [`Filesystem::release`].
    /// Default succeeds with handle `0`.
    fn open(&self, _path: &Path, _flags: i32) -> FsResult<u64> {
        Ok(0)
    }

    /// Read up to `size` bytes starting at `offset`. Returning fewer than
    /// `size` bytes is interpreted by libfuse-t as EOF — the standard
    /// POSIX semantics.
    fn read(&self, path: &Path, offset: u64, size: usize, fh: u64) -> FsResult<Vec<u8>>;

    /// Called when a previously-opened handle is released. Default is
    /// no-op.
    fn release(&self, _path: &Path, _fh: u64) -> FsResult<()> {
        Ok(())
    }

    /// Open a directory for enumeration. Default succeeds with handle `0`.
    fn opendir(&self, _path: &Path, _flags: i32) -> FsResult<u64> {
        Ok(0)
    }

    /// List the entries of a directory. `.` and `..` are supplied
    /// automatically by the libfuse-t-rs trampoline — the caller returns
    /// only the real children.
    fn readdir(&self, path: &Path) -> FsResult<Vec<DirEntry>>;

    /// Release a directory handle. Default no-op.
    fn releasedir(&self, _path: &Path, _fh: u64) -> FsResult<()> {
        Ok(())
    }

    /// Permission check hook. Default allows everything — permissions
    /// are enforced by the on-chain `Fs` agent, not by the FUSE layer.
    fn access(&self, _path: &Path, _mask: i32) -> FsResult<()> {
        Ok(())
    }

    /// Write `data` to `path` starting at `offset`. Default returns
    /// `NotSupported`; override on a writable filesystem. Return the
    /// number of bytes written.
    fn write(&self, _path: &Path, _offset: u64, _data: &[u8], _fh: u64) -> FsResult<usize> {
        Err(FsError::NotSupported)
    }

    /// Create a new empty file. Default returns `NotSupported`.
    fn create(&self, _path: &Path, _mode: u32, _flags: i32) -> FsResult<u64> {
        Err(FsError::NotSupported)
    }

    /// Create a directory. Default returns `NotSupported`.
    fn mkdir(&self, _path: &Path, _mode: u32) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    /// Remove a file. Default returns `NotSupported`.
    fn unlink(&self, _path: &Path) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    /// Remove an empty directory. Default returns `NotSupported`.
    fn rmdir(&self, _path: &Path) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    /// Rename a file or directory. Default returns `NotSupported`.
    fn rename(&self, _from: &Path, _to: &Path) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    /// Truncate a file. Default returns `NotSupported`.
    fn truncate(&self, _path: &Path, _size: u64) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    /// Change file mode. Default returns `NotSupported`.
    fn chmod(&self, _path: &Path, _mode: u32) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    /// Flush buffered writes for an open fd. Default no-op.
    fn flush(&self, _path: &Path, _fh: u64) -> FsResult<()> {
        Ok(())
    }
}
