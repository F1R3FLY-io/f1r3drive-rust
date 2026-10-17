//! End-to-end libfuse-t smoke test.
//!
//! Proves the Rust FFI around libfuse-t's high-level C API can:
//!
//! 1. Mount a FUSE filesystem via `fuse_mount` + `fuse_new`.
//! 2. Pump operations via `fuse_loop_mt` on a worker thread.
//! 3. Dispatch kernel ops to `extern "C"` Rust callbacks — specifically
//!    `getattr` for the mount root AND for arbitrary descendent paths
//!    (`/hello.txt`), which `fuser 0.14/0.18` could not do on fuse-t
//!    because fuser speaks the Linux `/dev/fuse` kernel protocol that
//!    fuse-t doesn't expose.
//! 4. Round-trip a `struct stat` from a Rust callback back to a POSIX
//!    `stat()` call: the test asserts `len == 5` on the child file,
//!    which can only be true if our `fuse_operations` struct layout
//!    matches the C ABI libfuse-t was compiled with.
//!
//! # Readdir / "Operation not permitted"
//!
//! `std::fs::read_dir(mountpoint)` returns `EPERM` on macOS unless the
//! terminal / parent process has "Network Volumes" access granted in
//! *System Settings → Privacy & Security → Files and Folders*. This is
//! documented in fuse-t's README: fuse-t mounts via NFSv4, so macOS's
//! TCC treats the mount as a network volume. The test does **not**
//! assert on readdir succeeding — the getattr-based path dispatch
//! assertion is sufficient to prove the FFI is wired correctly.
//!
//! # One test per process
//!
//! Observation state is in `static` atomics because `extern "C"`
//! callbacks can't capture closures. `cargo test` runs each `#[test]`
//! in its own process so this is fine.

#![cfg(target_os = "macos")]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};
use std::ptr;
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use libfuse_t_sys::{
    fuse, fuse_args, fuse_destroy, fuse_exit, fuse_file_info, fuse_fill_dir_t, fuse_loop_mt,
    fuse_mount, fuse_new, fuse_operations, fuse_operations_size, fuse_unmount,
};

static GETATTR_ROOT_CALLS: AtomicUsize = AtomicUsize::new(0);
static GETATTR_CHILD_CALLS: AtomicUsize = AtomicUsize::new(0);
static READDIR_CALLS: AtomicUsize = AtomicUsize::new(0);
static ACTIVE_FS: AtomicPtr<fuse> = AtomicPtr::new(ptr::null_mut());
static MOUNTPOINT: Mutex<Option<CString>> = Mutex::new(None);

const CHILD_PATH: &str = "/hello.txt";
const CHILD_SIZE: libc::off_t = 5; // "hello"

unsafe extern "C" fn op_getattr(path: *const c_char, stbuf: *mut libc::stat) -> c_int {
    let path = CStr::from_ptr(path).to_string_lossy();
    ptr::write_bytes(stbuf, 0, 1);
    let uid = libc::getuid();
    let gid = libc::getgid();
    match path.as_ref() {
        "/" => {
            GETATTR_ROOT_CALLS.fetch_add(1, Ordering::Relaxed);
            (*stbuf).st_mode = libc::S_IFDIR | 0o755;
            (*stbuf).st_nlink = 2;
            (*stbuf).st_uid = uid;
            (*stbuf).st_gid = gid;
            (*stbuf).st_blksize = 4096;
            0
        }
        p if p == CHILD_PATH => {
            GETATTR_CHILD_CALLS.fetch_add(1, Ordering::Relaxed);
            (*stbuf).st_mode = libc::S_IFREG | 0o644;
            (*stbuf).st_nlink = 1;
            (*stbuf).st_uid = uid;
            (*stbuf).st_gid = gid;
            (*stbuf).st_size = CHILD_SIZE;
            (*stbuf).st_blksize = 4096;
            (*stbuf).st_blocks = 1;
            0
        }
        _ => -libc::ENOENT,
    }
}

unsafe extern "C" fn op_readdir(
    path: *const c_char,
    buf: *mut c_void,
    filler: fuse_fill_dir_t,
    _offset: libc::off_t,
    _fi: *mut fuse_file_info,
) -> c_int {
    let path = CStr::from_ptr(path).to_string_lossy();
    if path != "/" {
        return -libc::ENOTDIR;
    }
    READDIR_CALLS.fetch_add(1, Ordering::Relaxed);
    let filler = filler.expect("filler must be non-null");

    let dot = CString::new(".").unwrap();
    let dotdot = CString::new("..").unwrap();
    let hello = CString::new("hello.txt").unwrap();

    filler(buf, dot.as_ptr(), ptr::null(), 0);
    filler(buf, dotdot.as_ptr(), ptr::null(), 0);
    filler(buf, hello.as_ptr(), ptr::null(), 0);
    0
}

unsafe extern "C" fn op_open(_path: *const c_char, _fi: *mut fuse_file_info) -> c_int {
    0
}

unsafe extern "C" fn op_read(
    _path: *const c_char,
    buf: *mut c_char,
    size: usize,
    offset: libc::off_t,
    _fi: *mut fuse_file_info,
) -> c_int {
    let content = b"hello";
    let start = offset.max(0) as usize;
    if start >= content.len() {
        return 0;
    }
    let avail = (content.len() - start).min(size);
    ptr::copy_nonoverlapping(content.as_ptr().add(start), buf as *mut u8, avail);
    avail as c_int
}

#[test]
#[ignore = "requires a real fuse-t install with mount privileges; CI runners can't actually mount"]
fn libfuse_t_dispatches_path_ops() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mountpoint_s = tmp.path().to_path_buf();
    let mountpoint_c = CString::new(mountpoint_s.as_os_str().to_str().expect("utf-8"))
        .expect("mountpoint has no NUL");
    *MOUNTPOINT.lock().unwrap() = Some(mountpoint_c.clone());

    let progname = CString::new("libfuse-t-smoke").unwrap();
    let mut argv_c: Vec<*mut c_char> = vec![progname.as_ptr() as *mut c_char, ptr::null_mut()];
    let args = fuse_args {
        argc: 1,
        argv: argv_c.as_mut_ptr(),
        allocated: 0,
    };

    let chan = unsafe { fuse_mount(mountpoint_c.as_ptr(), &args) };
    assert!(!chan.is_null(), "fuse_mount returned NULL — mount failed");

    let ops = fuse_operations {
        getattr: Some(op_getattr),
        readdir: Some(op_readdir),
        open: Some(op_open),
        read: Some(op_read),
        ..fuse_operations::default()
    };

    let fs = unsafe {
        fuse_new(
            chan,
            &args,
            &ops as *const _,
            fuse_operations_size(),
            ptr::null_mut(),
        )
    };
    assert!(!fs.is_null(), "fuse_new returned NULL");

    ACTIVE_FS.store(fs, Ordering::SeqCst);

    let loop_thread = std::thread::spawn(move || {
        let fs = ACTIVE_FS.load(Ordering::SeqCst);
        unsafe { fuse_loop_mt(fs) }
    });

    // Watchdog: forces unmount if the test gets stuck.
    let watchdog_mountpoint = mountpoint_c.clone();
    let _watchdog = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_secs(30));
        let fs = ACTIVE_FS.load(Ordering::SeqCst);
        if !fs.is_null() {
            unsafe {
                fuse_exit(fs);
                fuse_unmount(watchdog_mountpoint.as_ptr(), ptr::null_mut());
            }
        }
    });

    // Poll until the mount handshake has fired at least one root getattr.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if std::fs::metadata(&mountpoint_s).is_ok()
            && GETATTR_ROOT_CALLS.load(Ordering::Relaxed) > 0
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        GETATTR_ROOT_CALLS.load(Ordering::Relaxed) > 0,
        "root getattr never fired within 10s"
    );

    // The real proof: stat an arbitrary descendent path. Fuser 0.14/0.18
    // on fuse-t can't do this — the path never reaches userspace. Here
    // it must round-trip through our op_getattr with the correct string.
    let child_path = mountpoint_s.join("hello.txt");
    let md = std::fs::metadata(&child_path).expect("stat child");
    assert_eq!(md.len(), CHILD_SIZE as u64, "stat size round-trips");
    assert!(md.is_file(), "stat kind round-trips");
    assert!(
        GETATTR_CHILD_CALLS.load(Ordering::Relaxed) > 0,
        "op_getattr(\"/hello.txt\") never fired"
    );

    // readdir is best-effort — it fails with EPERM unless the terminal
    // has "Network Volumes" access granted (see module docstring).
    match std::fs::read_dir(&mountpoint_s) {
        Ok(iter) => {
            let names: Vec<String> = iter
                .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
                .collect();
            eprintln!("read_dir entries: {names:?}");
            assert!(
                READDIR_CALLS.load(Ordering::Relaxed) > 0,
                "read_dir succeeded without triggering op_readdir — ABI mismatch?"
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "read_dir blocked by macOS Network Volumes TCC — expected on CI/sandboxed shells. \
                 Grant Network Volumes access in System Settings to exercise this path."
            );
        }
        Err(e) => panic!("read_dir failed with unexpected error: {e}"),
    }

    unsafe {
        fuse_exit(fs);
        fuse_unmount(mountpoint_c.as_ptr(), chan);
    }
    let _ = loop_thread.join();
    unsafe { fuse_destroy(fs) };

    *MOUNTPOINT.lock().unwrap() = None;
}
