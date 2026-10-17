//! Attribute and directory-entry types returned by `Filesystem` methods.
//!
//! Mirrored closely to libfuse's `struct stat` and the `fuse_fill_dir_t`
//! callback contract, but shaped as plain Rust values.

use std::time::{Duration, SystemTime};

/// What an entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    Regular,
    Directory,
    /// Something libfuse-t can't represent as a regular file or dir.
    /// We clamp to RegularFile at the C ABI boundary.
    Other,
}

impl FileKind {
    /// POSIX st_mode bit pattern for the file type portion.
    ///
    /// `libc::S_IF*` constants are `u16` on macOS (via `mode_t = u16`)
    /// and `u32` on Linux (via `mode_t = u32`), so the explicit `as
    /// u32` cast is required on macOS and a no-op on Linux. We silence
    /// clippy's cross-platform-redundant-cast warning rather than
    /// branching the method body per target.
    #[allow(clippy::unnecessary_cast)]
    pub fn mode_bits(self) -> u32 {
        match self {
            FileKind::Regular => libc::S_IFREG as u32,
            FileKind::Directory => libc::S_IFDIR as u32,
            FileKind::Other => libc::S_IFREG as u32,
        }
    }
}

/// Everything we need to populate a `struct stat` reply.
#[derive(Debug, Clone)]
pub struct FileAttr {
    pub kind: FileKind,
    /// Low 12 permission bits (`rwxrwxrwx` + setuid/setgid/sticky).
    pub perm: u16,
    /// Length in bytes. Zero for dirs.
    pub size: u64,
    /// Hard-link count. Dirs typically report `2`.
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub atime: SystemTime,
    pub mtime: SystemTime,
    pub ctime: SystemTime,
    /// 512-byte block count. If unset, we compute from `size`.
    pub blocks: Option<u64>,
    /// Preferred I/O block size.
    pub blksize: u32,
}

impl FileAttr {
    pub fn dir(uid: u32, gid: u32) -> Self {
        Self {
            kind: FileKind::Directory,
            perm: 0o755,
            size: 0,
            nlink: 2,
            uid,
            gid,
            atime: SystemTime::UNIX_EPOCH,
            mtime: SystemTime::UNIX_EPOCH,
            ctime: SystemTime::UNIX_EPOCH,
            blocks: None,
            blksize: 4096,
        }
    }

    pub fn file(uid: u32, gid: u32, size: u64) -> Self {
        Self {
            kind: FileKind::Regular,
            perm: 0o644,
            size,
            nlink: 1,
            uid,
            gid,
            atime: SystemTime::UNIX_EPOCH,
            mtime: SystemTime::UNIX_EPOCH,
            ctime: SystemTime::UNIX_EPOCH,
            blocks: None,
            blksize: 4096,
        }
    }

    /// Populate a `libc::stat`. Zero-inits the whole thing first.
    ///
    /// # Safety
    ///
    /// `stbuf` must be a valid, writable `*mut libc::stat`.
    pub unsafe fn write_to(&self, stbuf: *mut libc::stat) {
        std::ptr::write_bytes(stbuf, 0, 1);
        (*stbuf).st_mode = (self.kind.mode_bits() | (self.perm as u32)) as libc::mode_t;
        (*stbuf).st_nlink = self.nlink as libc::nlink_t;
        (*stbuf).st_uid = self.uid;
        (*stbuf).st_gid = self.gid;
        (*stbuf).st_size = self.size as libc::off_t;
        let blocks = self.blocks.unwrap_or_else(|| self.size.div_ceil(512));
        (*stbuf).st_blocks = blocks as libc::blkcnt_t;
        (*stbuf).st_blksize = self.blksize as libc::blksize_t;
        (*stbuf).st_atime = system_time_to_secs(self.atime);
        (*stbuf).st_mtime = system_time_to_secs(self.mtime);
        (*stbuf).st_ctime = system_time_to_secs(self.ctime);
    }
}

fn system_time_to_secs(t: SystemTime) -> libc::time_t {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
        .min(libc::time_t::MAX as u64) as libc::time_t
}

/// One row returned from a directory listing.
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub kind: FileKind,
}

impl DirEntry {
    pub fn new(name: impl Into<String>, kind: FileKind) -> Self {
        Self {
            name: name.into(),
            kind,
        }
    }
}
