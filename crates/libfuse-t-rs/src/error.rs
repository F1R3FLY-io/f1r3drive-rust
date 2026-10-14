//! `FsError` — the result type returned by `Filesystem` methods.
//!
//! Values convert to libc errno codes at the C ABI boundary; callbacks
//! return `-errno` to libfuse-t.

use thiserror::Error;

/// Convenience alias every `Filesystem` method returns.
pub type FsResult<T> = Result<T, FsError>;

/// Enumerated POSIX errno subset relevant to a FUSE filesystem.
///
/// We don't try to cover every errno — the common ones here map directly
/// to what libfuse-t exposes to callers. Anything else goes through
/// [`FsError::Errno`] with the raw code.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum FsError {
    #[error("ENOENT: no such file or directory")]
    NotFound,
    #[error("EACCES: permission denied")]
    PermissionDenied,
    #[error("EEXIST: entry already exists")]
    AlreadyExists,
    #[error("ENOTDIR: not a directory")]
    NotADirectory,
    #[error("EISDIR: is a directory")]
    IsADirectory,
    #[error("EINVAL: invalid argument")]
    InvalidArgument,
    #[error("ENOSYS: not supported")]
    NotSupported,
    #[error("EIO: I/O error")]
    Io,
    #[error("EBUSY: resource busy")]
    Busy,
    #[error("EDQUOT: quota exceeded")]
    QuotaExceeded,
    /// Fallback for errnos not enumerated above. The inner value is a
    /// positive errno (we negate it at the ABI boundary).
    #[error("errno {0}")]
    Errno(i32),
}

impl FsError {
    /// Return the positive errno value this error maps to.
    pub fn to_errno(self) -> i32 {
        match self {
            FsError::NotFound => libc::ENOENT,
            FsError::PermissionDenied => libc::EACCES,
            FsError::AlreadyExists => libc::EEXIST,
            FsError::NotADirectory => libc::ENOTDIR,
            FsError::IsADirectory => libc::EISDIR,
            FsError::InvalidArgument => libc::EINVAL,
            FsError::NotSupported => libc::ENOSYS,
            FsError::Io => libc::EIO,
            FsError::Busy => libc::EBUSY,
            FsError::QuotaExceeded => libc::EDQUOT,
            FsError::Errno(e) => e,
        }
    }
}

impl From<i32> for FsError {
    fn from(errno: i32) -> Self {
        match errno {
            libc::ENOENT => FsError::NotFound,
            libc::EACCES => FsError::PermissionDenied,
            libc::EEXIST => FsError::AlreadyExists,
            libc::ENOTDIR => FsError::NotADirectory,
            libc::EISDIR => FsError::IsADirectory,
            libc::EINVAL => FsError::InvalidArgument,
            libc::ENOSYS => FsError::NotSupported,
            libc::EIO => FsError::Io,
            libc::EBUSY => FsError::Busy,
            libc::EDQUOT => FsError::QuotaExceeded,
            other => FsError::Errno(other),
        }
    }
}
