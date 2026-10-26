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

    /// Make a filesystem node. fuse-t's go-nfsv4 bridge invokes `mknod`
    /// (not `create`) when the client is NFSv4 and the FUSE op is
    /// OPEN(create). Default delegates to `create` so filesystems that
    /// only implement one get the other for free.
    fn mknod(&self, path: &Path, mode: u32, _rdev: u64) -> FsResult<()> {
        self.create(path, mode, 0).map(|_| ())
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

    /// Report volume stats. Default advertises a large, mostly-empty
    /// volume so Finder's free-space check during Copy doesn't bail
    /// with "not enough free space".
    fn statfs(&self, _path: &Path) -> FsResult<StatVfs> {
        Ok(StatVfs::default())
    }

    /// Set an extended attribute. Default is a no-op success — a
    /// filesystem that doesn't persist xattrs still has to accept
    /// writes cleanly, otherwise macOS `mv`'s `copyfile(3)` post-copy
    /// step surfaces "unable to move extended attributes and ACL".
    /// Override to actually persist.
    fn setxattr(
        &self,
        _path: &Path,
        _name: &str,
        _value: &[u8],
        _flags: i32,
    ) -> FsResult<()> {
        Ok(())
    }

    /// Read an extended attribute. Default returns `NotFound` which
    /// the trampoline encodes as `-ENOATTR` — the standard "I don't
    /// have this xattr" response. Callers (including macOS's
    /// `copyfile`) handle ENOATTR gracefully.
    fn getxattr(&self, _path: &Path, _name: &str) -> FsResult<Vec<u8>> {
        Err(FsError::NotFound)
    }

    /// List extended-attribute names. Default returns an empty list;
    /// callers see "no xattrs" and proceed.
    fn listxattr(&self, _path: &Path) -> FsResult<Vec<String>> {
        Ok(Vec::new())
    }

    /// Remove an extended attribute. Default no-op success — a
    /// filesystem with no xattrs reports "removed" rather than
    /// `ENOATTR` so a `removexattr` sweep after a copy doesn't fail
    /// loudly. Override to be strict.
    fn removexattr(&self, _path: &Path, _name: &str) -> FsResult<()> {
        Ok(())
    }
}

/// Volume-level stats returned by [`Filesystem::statfs`]. Mirrors the
/// relevant fields of `libc::statvfs`.
#[derive(Debug, Clone)]
pub struct StatVfs {
    pub bsize: u64,
    pub frsize: u64,
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub favail: u64,
    pub namemax: u64,
}

impl Default for StatVfs {
    fn default() -> Self {
        // 1 TiB of 4-KiB blocks, 99% free. Picked large enough that
        // every Finder copy-size precheck comfortably fits.
        let bsize = 4096u64;
        let blocks = 1u64 << 28; // 2^28 * 4KiB = 1 TiB
        let bfree = blocks - (blocks / 100);
        Self {
            bsize,
            frsize: bsize,
            blocks,
            bfree,
            bavail: bfree,
            files: 1u64 << 24,
            ffree: 1u64 << 24,
            favail: 1u64 << 24,
            namemax: 255,
        }
    }
}
