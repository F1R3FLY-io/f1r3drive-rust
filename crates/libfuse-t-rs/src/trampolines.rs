//! `extern "C"` shims that libfuse-t invokes. Each one:
//!
//! 1. Pulls the boxed `dyn Filesystem` out of the per-request
//!    `fuse_context->private_data`.
//! 2. Decodes the C arguments (path, offset, flags, etc.) into Rust
//!    values.
//! 3. Calls the matching trait method.
//! 4. Encodes the `FsResult` back as a `-errno` return.
//!
//! All shims unwind-safe-ly: a panic in a trait method would otherwise
//! unwind across a C stack frame (undefined behavior), so each shim
//! wraps its body in `std::panic::catch_unwind` and returns `-EIO` on a
//! panic. Only `tracing` logs the panic — we deliberately swallow it so
//! the FUSE loop can keep running.

use std::collections::hash_map::DefaultHasher;
use std::ffi::CStr;
use std::hash::{Hash, Hasher};
use std::os::raw::{c_char, c_int, c_void};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::ptr;

use libfuse_t_sys::{fuse_file_info, fuse_fill_dir_t, fuse_get_context};
use tracing::warn;

use crate::attr::{DirEntry, FileKind};
use crate::error::FsResult;
use crate::fs::Filesystem;

/// Stable path → inode. fuse-t presents mounts as NFSv4, which keys
/// its lookup cache on `st_ino`. Returning 0 (the zero-filled default
/// from `FileAttr::write_to`) leaves fuse-t to synthesize an inode,
/// but the synthesis isn't stable across getattr calls on nested
/// paths — different directories inside the mount can end up sharing
/// the same inode and the NFS client collapses their lookup cache
/// entries. Hash the path, OR in a high bit so we never return 0
/// (which libfuse treats as "unset").
fn path_ino(path: &Path) -> u64 {
    let mut h = DefaultHasher::new();
    path.hash(&mut h);
    h.finish() | (1 << 63)
}

/// Owning box of the user's filesystem, kept alive for the lifetime of
/// the mount. We lose the type parameter at this boundary (every C
/// callback has one, fixed, static signature).
pub(crate) type BoxedFs = Box<dyn Filesystem>;

/// Retrieve the current `&dyn Filesystem` from libfuse-t's per-request
/// context. Safe to call only from inside a FUSE callback.
///
/// # Safety
///
/// The pointer was published to libfuse-t by `fuse_new`; libfuse-t
/// hands it back verbatim via `fuse_get_context()->private_data`.
unsafe fn current_fs() -> Option<&'static dyn Filesystem> {
    let ctx = fuse_get_context();
    if ctx.is_null() {
        return None;
    }
    let private = (*ctx).private_data;
    if private.is_null() {
        return None;
    }
    let boxed = &*(private as *const BoxedFs);
    Some(boxed.as_ref())
}

/// Build an `&Path` from a C string. All libfuse-t paths are
/// NUL-terminated UTF-8 (on macOS, the kernel sends UTF-8 to the NFS
/// server which bridges to libfuse-t).
unsafe fn c_to_path<'a>(c: *const c_char) -> Option<&'a Path> {
    if c.is_null() {
        return None;
    }
    let cstr = CStr::from_ptr(c);
    cstr.to_str().ok().map(Path::new)
}

/// Map a `FsResult<()>` to a POSIX return value (0 on ok, -errno on err).
fn ok_or_errno(result: FsResult<()>) -> c_int {
    match result {
        Ok(()) => 0,
        Err(e) => -e.to_errno(),
    }
}

/// Run `body` with panic protection; log + return -EIO if it panics.
fn safe<F: FnOnce() -> c_int>(name: &'static str, body: F) -> c_int {
    let r = catch_unwind(AssertUnwindSafe(body));
    match r {
        Ok(code) => code,
        Err(_) => {
            warn!(callback = name, "FUSE callback panicked — returning -EIO");
            -libc::EIO
        }
    }
}

// -------------------- Callback shims --------------------

pub(crate) unsafe extern "C" fn op_getattr(path: *const c_char, stbuf: *mut libc::stat) -> c_int {
    safe("getattr", || {
        let Some(fs) = current_fs() else {
            return -libc::EIO;
        };
        let Some(path) = c_to_path(path) else {
            return -libc::EINVAL;
        };
        match fs.getattr(path) {
            Ok(attr) => {
                attr.write_to(stbuf);
                (*stbuf).st_ino = path_ino(path) as libc::ino_t;
                0
            }
            Err(e) => -e.to_errno(),
        }
    })
}

pub(crate) unsafe extern "C" fn op_open(path: *const c_char, _fi: *mut fuse_file_info) -> c_int {
    safe("open", || {
        let Some(fs) = current_fs() else {
            return -libc::EIO;
        };
        let Some(path) = c_to_path(path) else {
            return -libc::EINVAL;
        };
        // We don't peek at fi->flags for now; the Filesystem trait can
        // ignore flags and the common case Just Works.
        match fs.open(path, 0) {
            // libfuse's default is to drop our returned fh. If the user
            // needs it back on read/release, this crate's version 2
            // will stash it in fi->fh. For v1 the Filesystem gets a 0 fh
            // and must look up state by path.
            Ok(_fh) => 0,
            Err(e) => -e.to_errno(),
        }
    })
}

pub(crate) unsafe extern "C" fn op_release(path: *const c_char, _fi: *mut fuse_file_info) -> c_int {
    safe("release", || {
        let Some(fs) = current_fs() else {
            return -libc::EIO;
        };
        let Some(path) = c_to_path(path) else {
            return -libc::EINVAL;
        };
        ok_or_errno(fs.release(path, 0))
    })
}

pub(crate) unsafe extern "C" fn op_read(
    path: *const c_char,
    buf: *mut c_char,
    size: usize,
    offset: libc::off_t,
    _fi: *mut fuse_file_info,
) -> c_int {
    safe("read", || {
        let Some(fs) = current_fs() else {
            return -libc::EIO;
        };
        let Some(path) = c_to_path(path) else {
            return -libc::EINVAL;
        };
        let off = offset.max(0) as u64;
        match fs.read(path, off, size, 0) {
            Ok(data) => {
                let n = data.len().min(size);
                if n > 0 {
                    ptr::copy_nonoverlapping(data.as_ptr(), buf as *mut u8, n);
                }
                n as c_int
            }
            Err(e) => -e.to_errno(),
        }
    })
}

pub(crate) unsafe extern "C" fn op_opendir(path: *const c_char, _fi: *mut fuse_file_info) -> c_int {
    safe("opendir", || {
        let Some(fs) = current_fs() else {
            return -libc::EIO;
        };
        let Some(path) = c_to_path(path) else {
            return -libc::EINVAL;
        };
        match fs.opendir(path, 0) {
            Ok(_) => 0,
            Err(e) => -e.to_errno(),
        }
    })
}

pub(crate) unsafe extern "C" fn op_releasedir(
    path: *const c_char,
    _fi: *mut fuse_file_info,
) -> c_int {
    safe("releasedir", || {
        let Some(fs) = current_fs() else {
            return -libc::EIO;
        };
        let Some(path) = c_to_path(path) else {
            return -libc::EINVAL;
        };
        ok_or_errno(fs.releasedir(path, 0))
    })
}

pub(crate) unsafe extern "C" fn op_readdir(
    path: *const c_char,
    buf: *mut c_void,
    filler: fuse_fill_dir_t,
    _offset: libc::off_t,
    _fi: *mut fuse_file_info,
) -> c_int {
    safe("readdir", || {
        let Some(fs) = current_fs() else {
            return -libc::EIO;
        };
        let Some(path) = c_to_path(path) else {
            return -libc::EINVAL;
        };
        let entries: Vec<DirEntry> = match fs.readdir(path) {
            Ok(v) => v,
            Err(e) => return -e.to_errno(),
        };
        let Some(filler) = filler else {
            return -libc::EIO;
        };

        // Emit `.` and `..` unconditionally so the Filesystem impl
        // doesn't have to.
        let dot = c"."; // CStr literal (nul-terminated).
        let dotdot = c"..";
        filler(buf, dot.as_ptr(), ptr::null(), 0);
        filler(buf, dotdot.as_ptr(), ptr::null(), 0);

        for entry in entries {
            // CStrings interned per-row; libfuse-t copies before we
            // return.
            let Ok(cname) = std::ffi::CString::new(entry.name.as_bytes()) else {
                continue;
            };
            // We don't fill stbuf per entry — libfuse-t will call
            // getattr() for each entry when it needs attrs. That matches
            // the simplest-correct libfuse2 readdir contract.
            let _ = entry.kind; // reserved for future readdirplus-style use
                                // Filler returns non-zero when the buffer is full.
            if filler(buf, cname.as_ptr(), ptr::null(), 0) != 0 {
                break;
            }
        }
        let _ = FileKind::Regular; // keep FileKind import live for future
        0
    })
}

pub(crate) unsafe extern "C" fn op_access(path: *const c_char, mask: c_int) -> c_int {
    safe("access", || {
        let Some(fs) = current_fs() else {
            return -libc::EIO;
        };
        let Some(path) = c_to_path(path) else {
            return -libc::EINVAL;
        };
        ok_or_errno(fs.access(path, mask))
    })
}

pub(crate) unsafe extern "C" fn op_write(
    path: *const c_char,
    buf: *const c_char,
    size: usize,
    offset: libc::off_t,
    _fi: *mut fuse_file_info,
) -> c_int {
    safe("write", || {
        let Some(fs) = current_fs() else {
            return -libc::EIO;
        };
        let Some(path) = c_to_path(path) else {
            return -libc::EINVAL;
        };
        let slice = if buf.is_null() || size == 0 {
            &[][..]
        } else {
            std::slice::from_raw_parts(buf as *const u8, size)
        };
        let off = offset.max(0) as u64;
        match fs.write(path, off, slice, 0) {
            Ok(n) => n as c_int,
            Err(e) => -e.to_errno(),
        }
    })
}

pub(crate) unsafe extern "C" fn op_create(
    path: *const c_char,
    mode: libc::mode_t,
    _fi: *mut fuse_file_info,
) -> c_int {
    safe("create", || {
        let Some(fs) = current_fs() else {
            return -libc::EIO;
        };
        let Some(path) = c_to_path(path) else {
            return -libc::EINVAL;
        };
        match fs.create(path, mode as u32, 0) {
            Ok(_) => 0,
            Err(e) => -e.to_errno(),
        }
    })
}

pub(crate) unsafe extern "C" fn op_statfs(path: *const c_char, stbuf: *mut libc::statvfs) -> c_int {
    safe("statfs", || {
        let Some(fs) = current_fs() else {
            return -libc::EIO;
        };
        let Some(path) = c_to_path(path) else {
            return -libc::EINVAL;
        };
        match fs.statfs(path) {
            Ok(sv) => {
                let out = &mut *stbuf;
                std::ptr::write_bytes(out as *mut libc::statvfs, 0, 1);
                out.f_bsize = sv.bsize as _;
                out.f_frsize = sv.frsize as _;
                out.f_blocks = sv.blocks as _;
                out.f_bfree = sv.bfree as _;
                out.f_bavail = sv.bavail as _;
                out.f_files = sv.files as _;
                out.f_ffree = sv.ffree as _;
                out.f_favail = sv.favail as _;
                out.f_namemax = sv.namemax as _;
                0
            }
            Err(e) => -e.to_errno(),
        }
    })
}

pub(crate) unsafe extern "C" fn op_mknod(
    path: *const c_char,
    mode: libc::mode_t,
    rdev: libc::dev_t,
) -> c_int {
    safe("mknod", || {
        let Some(fs) = current_fs() else {
            return -libc::EIO;
        };
        let Some(path) = c_to_path(path) else {
            return -libc::EINVAL;
        };
        ok_or_errno(fs.mknod(path, mode as u32, rdev as u64))
    })
}

pub(crate) unsafe extern "C" fn op_mkdir(path: *const c_char, mode: libc::mode_t) -> c_int {
    safe("mkdir", || {
        let Some(fs) = current_fs() else {
            return -libc::EIO;
        };
        let Some(path) = c_to_path(path) else {
            return -libc::EINVAL;
        };
        ok_or_errno(fs.mkdir(path, mode as u32))
    })
}

pub(crate) unsafe extern "C" fn op_unlink(path: *const c_char) -> c_int {
    safe("unlink", || {
        let Some(fs) = current_fs() else {
            return -libc::EIO;
        };
        let Some(path) = c_to_path(path) else {
            return -libc::EINVAL;
        };
        ok_or_errno(fs.unlink(path))
    })
}

pub(crate) unsafe extern "C" fn op_rmdir(path: *const c_char) -> c_int {
    safe("rmdir", || {
        let Some(fs) = current_fs() else {
            return -libc::EIO;
        };
        let Some(path) = c_to_path(path) else {
            return -libc::EINVAL;
        };
        ok_or_errno(fs.rmdir(path))
    })
}

pub(crate) unsafe extern "C" fn op_rename(from: *const c_char, to: *const c_char) -> c_int {
    safe("rename", || {
        let Some(fs) = current_fs() else {
            return -libc::EIO;
        };
        let (Some(from), Some(to)) = (c_to_path(from), c_to_path(to)) else {
            return -libc::EINVAL;
        };
        ok_or_errno(fs.rename(from, to))
    })
}

pub(crate) unsafe extern "C" fn op_truncate(path: *const c_char, size: libc::off_t) -> c_int {
    safe("truncate", || {
        let Some(fs) = current_fs() else {
            return -libc::EIO;
        };
        let Some(path) = c_to_path(path) else {
            return -libc::EINVAL;
        };
        ok_or_errno(fs.truncate(path, size.max(0) as u64))
    })
}

pub(crate) unsafe extern "C" fn op_chmod(path: *const c_char, mode: libc::mode_t) -> c_int {
    safe("chmod", || {
        let Some(fs) = current_fs() else {
            return -libc::EIO;
        };
        let Some(path) = c_to_path(path) else {
            return -libc::EINVAL;
        };
        ok_or_errno(fs.chmod(path, mode as u32))
    })
}

pub(crate) unsafe extern "C" fn op_flush(path: *const c_char, _fi: *mut fuse_file_info) -> c_int {
    safe("flush", || {
        let Some(fs) = current_fs() else {
            return -libc::EIO;
        };
        let Some(path) = c_to_path(path) else {
            return -libc::EINVAL;
        };
        ok_or_errno(fs.flush(path, 0))
    })
}

pub(crate) unsafe extern "C" fn op_destroy(private_data: *mut c_void) {
    if private_data.is_null() {
        return;
    }
    // Reclaim ownership and drop. After this returns, no further
    // callbacks can refer to the filesystem (libfuse-t has already
    // stopped dispatching).
    let boxed: Box<BoxedFs> = Box::from_raw(private_data as *mut BoxedFs);
    let _ = catch_unwind(AssertUnwindSafe(|| boxed.destroy()));
    drop(boxed);
}
