//! Raw FFI bindings to libfuse-t's high-level C API.
//!
//! libfuse-t is a userspace libfuse-2.9 implementation that bridges NFSv4
//! to the libfuse operation table. Unlike the Linux FUSE kernel driver
//! (which `fuser` targets), libfuse-t has no kernel component and no
//! `/dev/fuse` fd — the only way to drive it is to register `extern "C"`
//! callbacks in a `fuse_operations` table and call `fuse_new` +
//! `fuse_loop_mt`.
//!
//! This crate exposes only the raw FFI; the safe Rust wrapper lives in a
//! separate crate.
//!
//! # Platform
//!
//! Only macOS is supported. On Linux this crate is empty — downstream
//! crates should `#[cfg(target_os = "macos")]`-gate every use.
//!
//! # Prerequisites
//!
//! `brew install --cask fuse-t`.

#![cfg(target_os = "macos")]
#![allow(non_camel_case_types, non_snake_case, clippy::missing_safety_doc)]

use std::os::raw::{c_char, c_int, c_void};

/// Opaque libfuse handle returned by `fuse_new`.
#[repr(C)]
pub struct fuse {
    _opaque: [u8; 0],
}

/// Opaque libfuse channel returned by `fuse_mount`.
#[repr(C)]
pub struct fuse_chan {
    _opaque: [u8; 0],
}

/// Opaque per-session struct used by the signal handlers.
#[repr(C)]
pub struct fuse_session {
    _opaque: [u8; 0],
}

/// Opaque libfuse connection info passed to `init` callback.
#[repr(C)]
pub struct fuse_conn_info {
    _opaque: [u8; 0],
}

/// Opaque pollhandle.
#[repr(C)]
pub struct fuse_pollhandle {
    _opaque: [u8; 0],
}

/// Opaque bufvec (for write_buf / read_buf).
#[repr(C)]
pub struct fuse_bufvec {
    _opaque: [u8; 0],
}

/// Opaque setattr_x (Apple extension).
#[repr(C)]
pub struct setattr_x {
    _opaque: [u8; 0],
}

/// Opaque `fuse_file_info`. The real struct has `flags`, `fh`, and bit
/// flags; we don't need to peek into any of its fields from the smoke
/// test, so we treat it as opaque.
///
/// Callers who do need `fh` / `flags` should re-declare the struct here
/// with the actual layout; libfuse 2.9's definition is in
/// `fuse_common.h`.
#[repr(C)]
pub struct fuse_file_info {
    _opaque: [u8; 0],
}

/// Opaque fuse_dirh and fuse_dirfil (deprecated getdir path).
#[repr(C)]
pub struct fuse_dirh {
    _opaque: [u8; 0],
}
pub type fuse_dirh_t = *mut fuse_dirh;
pub type fuse_dirfil_t = Option<
    unsafe extern "C" fn(
        h: fuse_dirh_t,
        name: *const c_char,
        type_: c_int,
        ino: libc::ino_t,
    ) -> c_int,
>;

/// Argument vector passed into `fuse_mount` / `fuse_new`.
#[repr(C)]
pub struct fuse_args {
    pub argc: c_int,
    pub argv: *mut *mut c_char,
    pub allocated: c_int,
}

/// Readdir filler callback.
pub type fuse_fill_dir_t = Option<
    unsafe extern "C" fn(
        buf: *mut c_void,
        name: *const c_char,
        stbuf: *const libc::stat,
        off: libc::off_t,
    ) -> c_int,
>;

/// Processor type for `fuse_loop_mt_proc` — unused by this crate.
pub type fuse_processor_t =
    Option<unsafe extern "C" fn(f: *mut fuse, cmd: *mut c_void, data: *mut c_void)>;

/// libfuse 2.9 operation table on macOS (`fuse-t 1.2.9`), laid out
/// exactly as in `/usr/local/include/fuse/fuse.h`.
///
/// All operation pointers are `Option<fn_ptr>`: `None` = unimplemented
/// (nullptr), and libfuse falls back to its default error path (`ENOSYS`
/// for most ops, or a sensible default).
///
/// The `flag_*` bitfields are kept as a single `u32` because Rust's
/// stable ABI doesn't support bitfield layout. Setting it to `0` matches
/// the common "no special flags" case.
#[repr(C)]
pub struct fuse_operations {
    pub getattr: Option<unsafe extern "C" fn(path: *const c_char, stbuf: *mut libc::stat) -> c_int>,
    pub readlink:
        Option<unsafe extern "C" fn(path: *const c_char, buf: *mut c_char, size: usize) -> c_int>,
    pub getdir: Option<
        unsafe extern "C" fn(path: *const c_char, h: fuse_dirh_t, filler: fuse_dirfil_t) -> c_int,
    >,
    pub mknod: Option<
        unsafe extern "C" fn(path: *const c_char, mode: libc::mode_t, rdev: libc::dev_t) -> c_int,
    >,
    pub mkdir: Option<unsafe extern "C" fn(path: *const c_char, mode: libc::mode_t) -> c_int>,
    pub unlink: Option<unsafe extern "C" fn(path: *const c_char) -> c_int>,
    pub rmdir: Option<unsafe extern "C" fn(path: *const c_char) -> c_int>,
    pub symlink: Option<unsafe extern "C" fn(from: *const c_char, to: *const c_char) -> c_int>,
    pub rename: Option<unsafe extern "C" fn(from: *const c_char, to: *const c_char) -> c_int>,
    pub link: Option<unsafe extern "C" fn(from: *const c_char, to: *const c_char) -> c_int>,
    pub chmod: Option<unsafe extern "C" fn(path: *const c_char, mode: libc::mode_t) -> c_int>,
    pub chown: Option<
        unsafe extern "C" fn(path: *const c_char, uid: libc::uid_t, gid: libc::gid_t) -> c_int,
    >,
    pub truncate: Option<unsafe extern "C" fn(path: *const c_char, size: libc::off_t) -> c_int>,
    pub utime: Option<unsafe extern "C" fn(path: *const c_char, buf: *mut libc::utimbuf) -> c_int>,
    pub open: Option<unsafe extern "C" fn(path: *const c_char, fi: *mut fuse_file_info) -> c_int>,
    pub read: Option<
        unsafe extern "C" fn(
            path: *const c_char,
            buf: *mut c_char,
            size: usize,
            offset: libc::off_t,
            fi: *mut fuse_file_info,
        ) -> c_int,
    >,
    pub write: Option<
        unsafe extern "C" fn(
            path: *const c_char,
            buf: *const c_char,
            size: usize,
            offset: libc::off_t,
            fi: *mut fuse_file_info,
        ) -> c_int,
    >,
    pub statfs:
        Option<unsafe extern "C" fn(path: *const c_char, stbuf: *mut libc::statvfs) -> c_int>,
    pub flush: Option<unsafe extern "C" fn(path: *const c_char, fi: *mut fuse_file_info) -> c_int>,
    pub release:
        Option<unsafe extern "C" fn(path: *const c_char, fi: *mut fuse_file_info) -> c_int>,
    pub fsync: Option<
        unsafe extern "C" fn(
            path: *const c_char,
            datasync: c_int,
            fi: *mut fuse_file_info,
        ) -> c_int,
    >,
    /// macOS variant takes an extra `uint32_t position` arg.
    pub setxattr: Option<
        unsafe extern "C" fn(
            path: *const c_char,
            name: *const c_char,
            value: *const c_char,
            size: usize,
            flags: c_int,
            position: u32,
        ) -> c_int,
    >,
    /// macOS variant.
    pub getxattr: Option<
        unsafe extern "C" fn(
            path: *const c_char,
            name: *const c_char,
            value: *mut c_char,
            size: usize,
            position: u32,
        ) -> c_int,
    >,
    pub listxattr:
        Option<unsafe extern "C" fn(path: *const c_char, list: *mut c_char, size: usize) -> c_int>,
    pub removexattr:
        Option<unsafe extern "C" fn(path: *const c_char, name: *const c_char) -> c_int>,
    pub opendir:
        Option<unsafe extern "C" fn(path: *const c_char, fi: *mut fuse_file_info) -> c_int>,
    pub readdir: Option<
        unsafe extern "C" fn(
            path: *const c_char,
            buf: *mut c_void,
            filler: fuse_fill_dir_t,
            offset: libc::off_t,
            fi: *mut fuse_file_info,
        ) -> c_int,
    >,
    pub releasedir:
        Option<unsafe extern "C" fn(path: *const c_char, fi: *mut fuse_file_info) -> c_int>,
    pub fsyncdir: Option<
        unsafe extern "C" fn(
            path: *const c_char,
            datasync: c_int,
            fi: *mut fuse_file_info,
        ) -> c_int,
    >,
    pub init: Option<unsafe extern "C" fn(conn: *mut fuse_conn_info) -> *mut c_void>,
    pub destroy: Option<unsafe extern "C" fn(user_data: *mut c_void)>,
    pub access: Option<unsafe extern "C" fn(path: *const c_char, mask: c_int) -> c_int>,
    pub create: Option<
        unsafe extern "C" fn(
            path: *const c_char,
            mode: libc::mode_t,
            fi: *mut fuse_file_info,
        ) -> c_int,
    >,
    pub ftruncate: Option<
        unsafe extern "C" fn(
            path: *const c_char,
            size: libc::off_t,
            fi: *mut fuse_file_info,
        ) -> c_int,
    >,
    pub fgetattr: Option<
        unsafe extern "C" fn(
            path: *const c_char,
            stbuf: *mut libc::stat,
            fi: *mut fuse_file_info,
        ) -> c_int,
    >,
    pub lock: Option<
        unsafe extern "C" fn(
            path: *const c_char,
            fi: *mut fuse_file_info,
            cmd: c_int,
            lock: *mut libc::flock,
        ) -> c_int,
    >,
    pub utimens:
        Option<unsafe extern "C" fn(path: *const c_char, tv: *const libc::timespec) -> c_int>,
    pub bmap:
        Option<unsafe extern "C" fn(path: *const c_char, blocksize: usize, idx: *mut u64) -> c_int>,
    /// Packed bitfield block from the header: flag_nullpath_ok:1,
    /// flag_nopath:1, flag_utime_omit_ok:1, flag_reserved:29. We expose
    /// it as a single `u32`; `0` matches "no flags set" which is what we
    /// want for the smoke test.
    pub flags: u32,
    pub ioctl: Option<
        unsafe extern "C" fn(
            path: *const c_char,
            cmd: c_int,
            arg: *mut c_void,
            fi: *mut fuse_file_info,
            flags: u32,
            data: *mut c_void,
        ) -> c_int,
    >,
    pub poll: Option<
        unsafe extern "C" fn(
            path: *const c_char,
            fi: *mut fuse_file_info,
            ph: *mut fuse_pollhandle,
            reventsp: *mut u32,
        ) -> c_int,
    >,
    pub write_buf: Option<
        unsafe extern "C" fn(
            path: *const c_char,
            buf: *mut fuse_bufvec,
            off: libc::off_t,
            fi: *mut fuse_file_info,
        ) -> c_int,
    >,
    pub read_buf: Option<
        unsafe extern "C" fn(
            path: *const c_char,
            bufp: *mut *mut fuse_bufvec,
            size: usize,
            off: libc::off_t,
            fi: *mut fuse_file_info,
        ) -> c_int,
    >,
    pub flock: Option<
        unsafe extern "C" fn(path: *const c_char, fi: *mut fuse_file_info, op: c_int) -> c_int,
    >,
    pub fallocate: Option<
        unsafe extern "C" fn(
            path: *const c_char,
            mode: c_int,
            offset: libc::off_t,
            length: libc::off_t,
            fi: *mut fuse_file_info,
        ) -> c_int,
    >,
    // ---------- Apple-only tail (fuse.h __APPLE__ block) --------------
    pub reserved00: Option<
        unsafe extern "C" fn(
            _: *mut c_void,
            _: *mut c_void,
            _: *mut c_void,
            _: *mut c_void,
            _: *mut c_void,
            _: *mut c_void,
            _: *mut c_void,
            _: *mut c_void,
        ) -> c_int,
    >,
    pub reserved01: Option<
        unsafe extern "C" fn(
            _: *mut c_void,
            _: *mut c_void,
            _: *mut c_void,
            _: *mut c_void,
            _: *mut c_void,
            _: *mut c_void,
            _: *mut c_void,
            _: *mut c_void,
        ) -> c_int,
    >,
    pub renamex:
        Option<unsafe extern "C" fn(from: *const c_char, to: *const c_char, flags: u32) -> c_int>,
    pub statfs_x:
        Option<unsafe extern "C" fn(path: *const c_char, stbuf: *mut libc::statfs) -> c_int>,
    pub setvolname: Option<unsafe extern "C" fn(name: *const c_char) -> c_int>,
    pub exchange: Option<
        unsafe extern "C" fn(path1: *const c_char, path2: *const c_char, options: u64) -> c_int,
    >,
    pub getxtimes: Option<
        unsafe extern "C" fn(
            path: *const c_char,
            bkuptime: *mut libc::timespec,
            crtime: *mut libc::timespec,
        ) -> c_int,
    >,
    pub setbkuptime:
        Option<unsafe extern "C" fn(path: *const c_char, tv: *const libc::timespec) -> c_int>,
    pub setchgtime:
        Option<unsafe extern "C" fn(path: *const c_char, tv: *const libc::timespec) -> c_int>,
    pub setcrtime:
        Option<unsafe extern "C" fn(path: *const c_char, tv: *const libc::timespec) -> c_int>,
    pub chflags: Option<unsafe extern "C" fn(path: *const c_char, flags: u32) -> c_int>,
    pub setattr_x: Option<unsafe extern "C" fn(path: *const c_char, attr: *mut setattr_x) -> c_int>,
    pub fsetattr_x: Option<
        unsafe extern "C" fn(
            path: *const c_char,
            attr: *mut setattr_x,
            fi: *mut fuse_file_info,
        ) -> c_int,
    >,
}

impl Default for fuse_operations {
    fn default() -> Self {
        // All ops default to NULL (unimplemented); libfuse supplies defaults.
        // SAFETY: Option<fn ptr> is nullable and zero-init is a valid None;
        // u32 of 0 is also valid. The struct contains no non-nullable fields.
        unsafe { std::mem::zeroed() }
    }
}

/// Per-request context accessible via [`fuse_get_context`] inside any
/// callback. `private_data` is whatever we passed to `fuse_new`'s
/// `user_data`; the rest describe the calling process.
#[repr(C)]
pub struct fuse_context {
    pub fuse: *mut fuse,
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    pub pid: libc::pid_t,
    pub private_data: *mut c_void,
    pub umask: libc::mode_t,
}

extern "C" {
    /// Argv-style frontend. Blocks until the FS is unmounted. Returns 0
    /// on clean shutdown.
    pub fn fuse_main_real(
        argc: c_int,
        argv: *mut *mut c_char,
        op: *const fuse_operations,
        op_size: usize,
        user_data: *mut c_void,
    ) -> c_int;

    /// Low-level mount. Returns a channel on success; NULL on failure.
    pub fn fuse_mount(mountpoint: *const c_char, args: *const fuse_args) -> *mut fuse_chan;

    /// Create a FUSE instance bound to `ch`. The caller retains ownership
    /// of `op` for the lifetime of the returned handle.
    pub fn fuse_new(
        ch: *mut fuse_chan,
        args: *const fuse_args,
        op: *const fuse_operations,
        op_size: usize,
        user_data: *mut c_void,
    ) -> *mut fuse;

    /// Run the multi-threaded event loop. Returns when `fuse_exit` is
    /// called from another thread.
    pub fn fuse_loop_mt(f: *mut fuse) -> c_int;

    /// Request the loop to exit (safe to call from any thread).
    pub fn fuse_exit(f: *mut fuse);

    /// Unmount the filesystem. The caller then calls `fuse_destroy`.
    pub fn fuse_unmount(mountpoint: *const c_char, ch: *mut fuse_chan);

    /// Destroy the FUSE instance.
    pub fn fuse_destroy(f: *mut fuse);

    /// Get the per-request context — valid only while a FUSE callback is
    /// executing. `private_data` carries the `user_data` we passed to
    /// `fuse_new`.
    pub fn fuse_get_context() -> *mut fuse_context;
}

/// Size of the operation table — libfuse checks this against the one its
/// headers were compiled with and refuses to run if too small.
pub const fn fuse_operations_size() -> usize {
    std::mem::size_of::<fuse_operations>()
}
