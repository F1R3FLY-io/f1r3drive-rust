//! Mount lifecycle: foreground `mount()` and `spawn_mount()` with a
//! background session that unmounts on drop.

use std::ffi::CString;
use std::io;
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicPtr, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use libfuse_t_sys::{
    fuse, fuse_args, fuse_destroy, fuse_exit, fuse_loop_mt, fuse_mount, fuse_new, fuse_operations,
    fuse_operations_size, fuse_unmount,
};
use tracing::{info, warn};

use crate::fs::Filesystem;
use crate::trampolines::{
    op_access, op_chmod, op_create, op_destroy, op_flush, op_getattr, op_mkdir, op_mknod, op_open,
    op_opendir, op_read, op_readdir, op_release, op_releasedir, op_rename, op_rmdir, op_statfs,
    op_truncate, op_unlink, op_write, BoxedFs,
};

/// Options passed to [`mount`] / [`spawn_mount`].
#[derive(Debug, Clone, Default)]
pub struct MountOptions {
    /// String name used in `mount` output (`-o fsname=…`).
    pub fs_name: Option<String>,
    /// Finder volume name on macOS (`-o volname=…`).
    pub volume_name: Option<String>,
    /// Mount read-only.
    pub read_only: bool,
    /// Any additional `-o <opt>` strings to pass through unchanged. Use
    /// for libfuse options not covered above.
    pub extra: Vec<String>,
}

impl MountOptions {
    fn to_arg_strings(&self, prog: &str) -> Vec<CString> {
        let mut v = Vec::with_capacity(8);
        v.push(CString::new(prog).unwrap());
        let mut opts = Vec::new();
        if let Some(n) = &self.fs_name {
            opts.push(format!("fsname={n}"));
        }
        if let Some(n) = &self.volume_name {
            opts.push(format!("volname={n}"));
        }
        if self.read_only {
            opts.push("ro".to_string());
        }
        for e in &self.extra {
            opts.push(e.clone());
        }
        if !opts.is_empty() {
            v.push(CString::new("-o").unwrap());
            v.push(CString::new(opts.join(",")).unwrap());
        }
        v
    }
}

/// Build the raw `fuse_operations` table pointing at our trampolines.
/// All ops the trait exposes are wired; libfuse-t falls back to a
/// default (`ENOSYS`) for anything not set.
fn operations() -> fuse_operations {
    fuse_operations {
        getattr: Some(op_getattr),
        open: Some(op_open),
        release: Some(op_release),
        read: Some(op_read),
        write: Some(op_write),
        opendir: Some(op_opendir),
        releasedir: Some(op_releasedir),
        readdir: Some(op_readdir),
        access: Some(op_access),
        create: Some(op_create),
        mknod: Some(op_mknod),
        statfs: Some(op_statfs),
        mkdir: Some(op_mkdir),
        unlink: Some(op_unlink),
        rmdir: Some(op_rmdir),
        rename: Some(op_rename),
        truncate: Some(op_truncate),
        chmod: Some(op_chmod),
        flush: Some(op_flush),
        destroy: Some(op_destroy),
        ..fuse_operations::default()
    }
}

/// RAII wrapper around a mounted libfuse-t session. On drop it unmounts
/// and waits for the loop thread to join.
pub struct BackgroundSession {
    fs: AtomicPtr<fuse>,
    mountpoint: CString,
    loop_thread: Option<JoinHandle<()>>,
    chan: *mut libfuse_t_sys::fuse_chan,
    mountpoint_path: PathBuf,
}

// SAFETY: all raw pointers point into libfuse-t-owned state and are only
// touched inside `unsafe` blocks that respect its threading model.
unsafe impl Send for BackgroundSession {}
unsafe impl Sync for BackgroundSession {}

impl BackgroundSession {
    /// Request shutdown and wait for the loop thread. Called by Drop,
    /// but can be invoked explicitly for structured teardown.
    pub fn umount_and_join(&mut self) {
        let fs = self.fs.swap(ptr::null_mut(), Ordering::SeqCst);
        if fs.is_null() {
            return;
        }
        unsafe {
            fuse_exit(fs);
            fuse_unmount(self.mountpoint.as_ptr(), self.chan);
        }
        if let Some(t) = self.loop_thread.take() {
            if let Err(e) = t.join() {
                warn!(?e, "fuse_loop_mt thread panicked during join");
            }
        }
        unsafe { fuse_destroy(fs) };
    }

    /// Return the mountpoint this session is bound to.
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint_path
    }
}

impl Drop for BackgroundSession {
    fn drop(&mut self) {
        self.umount_and_join();
    }
}

/// Boxed-up state we have to keep alive for the whole mount: the
/// filesystem and the ops table it points at via trampolines.
struct SessionState {
    _fs: Arc<()>, // reserved for future use (per-mount counter)
    _ops: Box<fuse_operations>,
}

/// Spawn a background thread running the libfuse-t event loop and
/// return immediately with a handle whose drop unmounts.
pub fn spawn_mount<F>(
    fs: F,
    mountpoint: &Path,
    options: &MountOptions,
) -> io::Result<BackgroundSession>
where
    F: Filesystem,
{
    let (session, state) = start_session(fs, mountpoint, options)?;
    // Keep ops alive — libfuse-t retains the pointer we passed to fuse_new.
    // We leak it; the destroy callback drops the boxed FS, but the ops
    // table itself has nothing to drop (just pointers).
    std::mem::forget(state);
    Ok(session)
}

/// Mount in the foreground; blocks until unmounted. Returns Ok on clean
/// shutdown or an error on mount setup failure.
pub fn mount<F>(fs: F, mountpoint: &Path, options: &MountOptions) -> io::Result<()>
where
    F: Filesystem,
{
    let (mut session, state) = start_session(fs, mountpoint, options)?;
    std::mem::forget(state);
    // Block waiting for the session thread to finish on its own
    // (unmount via `umount(8)` from another process, SIGINT, etc.).
    if let Some(t) = session.loop_thread.take() {
        let _ = t.join();
    }
    // Explicit cleanup since loop_thread is already consumed.
    let fs_ptr = session.fs.swap(ptr::null_mut(), Ordering::SeqCst);
    if !fs_ptr.is_null() {
        unsafe {
            fuse_unmount(session.mountpoint.as_ptr(), session.chan);
            fuse_destroy(fs_ptr);
        }
    }
    // Prevent Drop from running umount_and_join again on an empty handle.
    std::mem::forget(session);
    Ok(())
}

fn start_session<F>(
    fs: F,
    mountpoint: &Path,
    options: &MountOptions,
) -> io::Result<(BackgroundSession, SessionState)>
where
    F: Filesystem,
{
    // Box the filesystem twice: inner Box<dyn Filesystem> erases the
    // concrete type for the trampolines; outer Box<Box<...>> gives us a
    // stable *mut c_void we can round-trip through libfuse-t.
    let boxed: BoxedFs = Box::new(fs);
    let boxed_outer: Box<BoxedFs> = Box::new(boxed);
    let user_data = Box::into_raw(boxed_outer) as *mut libc::c_void;

    let mountpoint_c = CString::new(
        mountpoint
            .as_os_str()
            .to_str()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "mountpoint not UTF-8"))?,
    )
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "mountpoint contains NUL"))?;

    let arg_strings = options.to_arg_strings("libfuse-t-rs");
    let mut argv_c: Vec<*mut c_char> = arg_strings
        .iter()
        .map(|s| s.as_ptr() as *mut c_char)
        .collect();
    argv_c.push(ptr::null_mut());
    let args = fuse_args {
        argc: arg_strings.len() as _,
        argv: argv_c.as_mut_ptr(),
        allocated: 0,
    };

    // SAFETY: fuse_mount is thread-safe, and we hand it NUL-terminated
    // strings that outlive the call.
    let chan = unsafe { fuse_mount(mountpoint_c.as_ptr(), &args) };
    if chan.is_null() {
        // We never got into libfuse — reclaim and drop the boxed FS.
        let _ = unsafe { Box::from_raw(user_data as *mut BoxedFs) };
        return Err(io::Error::other(
            "fuse_mount returned NULL (fuse-t unavailable?)",
        ));
    }

    let ops_box = Box::new(operations());
    let fs_ptr = unsafe {
        fuse_new(
            chan,
            &args,
            ops_box.as_ref() as *const _,
            fuse_operations_size(),
            user_data,
        )
    };
    if fs_ptr.is_null() {
        unsafe {
            fuse_unmount(mountpoint_c.as_ptr(), chan);
            let _ = Box::from_raw(user_data as *mut BoxedFs);
        }
        return Err(io::Error::other("fuse_new returned NULL"));
    }

    let fs_atomic = AtomicPtr::new(fs_ptr);
    // `*mut fuse` isn't `Send`; shuttle it across as a `usize` and
    // re-cast on the other side. The pointer is valid for the lifetime
    // of the mount: we only call `fuse_destroy` after the thread joins.
    let fs_addr = fs_ptr as usize;
    let mountpoint_path = mountpoint.to_path_buf();

    info!(mountpoint = %mountpoint.display(), "libfuse-t session mounted");

    let loop_thread = std::thread::Builder::new()
        .name("libfuse-t-loop".into())
        .spawn(move || {
            // SAFETY: the pointer is valid until we join this thread
            // from BackgroundSession::umount_and_join.
            let rc = unsafe { fuse_loop_mt(fs_addr as *mut fuse) };
            if rc != 0 {
                warn!(rc, "fuse_loop_mt returned non-zero");
            }
        })?;

    Ok((
        BackgroundSession {
            fs: fs_atomic,
            mountpoint: mountpoint_c,
            loop_thread: Some(loop_thread),
            chan,
            mountpoint_path,
        },
        SessionState {
            _fs: Arc::new(()),
            _ops: ops_box,
        },
    ))
}
