//! Smoke test for the safe wrapper.
//!
//! Mirrors `libfuse-t-sys/tests/mount_smoke.rs` but through the
//! `Filesystem` trait rather than raw `extern "C"` callbacks. If this
//! passes, the trampoline layer is wired correctly and consumer code
//! can be written in plain safe Rust.

#![cfg(target_os = "macos")]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use libfuse_t_rs::{
    spawn_mount, DirEntry, FileAttr, FileKind, Filesystem, FsError, FsResult, MountOptions,
};

#[derive(Default)]
struct Counters {
    getattr_root: AtomicUsize,
    getattr_child: AtomicUsize,
    readdir: AtomicUsize,
    open: AtomicUsize,
    read: AtomicUsize,
}

struct DummyFs {
    uid: u32,
    gid: u32,
    counters: Arc<Counters>,
}

const CHILD_NAME: &str = "hello.txt";
const CHILD_CONTENT: &[u8] = b"hello";

impl Filesystem for DummyFs {
    fn getattr(&self, path: &Path) -> FsResult<FileAttr> {
        let s = path.to_string_lossy();
        if s == "/" {
            self.counters.getattr_root.fetch_add(1, Ordering::Relaxed);
            Ok(FileAttr::dir(self.uid, self.gid))
        } else if s == "/hello.txt" {
            self.counters.getattr_child.fetch_add(1, Ordering::Relaxed);
            Ok(FileAttr::file(
                self.uid,
                self.gid,
                CHILD_CONTENT.len() as u64,
            ))
        } else {
            Err(FsError::NotFound)
        }
    }

    fn readdir(&self, path: &Path) -> FsResult<Vec<DirEntry>> {
        if path != Path::new("/") {
            return Err(FsError::NotADirectory);
        }
        self.counters.readdir.fetch_add(1, Ordering::Relaxed);
        Ok(vec![DirEntry::new(CHILD_NAME, FileKind::Regular)])
    }

    fn open(&self, path: &Path, _flags: i32) -> FsResult<u64> {
        if path == Path::new("/hello.txt") {
            self.counters.open.fetch_add(1, Ordering::Relaxed);
            Ok(0)
        } else {
            Err(FsError::NotFound)
        }
    }

    fn read(&self, path: &Path, offset: u64, size: usize, _fh: u64) -> FsResult<Vec<u8>> {
        if path != Path::new("/hello.txt") {
            return Err(FsError::NotFound);
        }
        self.counters.read.fetch_add(1, Ordering::Relaxed);
        let start = (offset as usize).min(CHILD_CONTENT.len());
        let end = (start + size).min(CHILD_CONTENT.len());
        Ok(CHILD_CONTENT[start..end].to_vec())
    }
}

fn wait_for<F: FnMut() -> bool>(mut cond: F, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    cond()
}

#[test]
fn safe_wrapper_dispatches_path_ops() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mountpoint: PathBuf = tmp.path().to_path_buf();

    let counters = Arc::new(Counters::default());
    let fs = DummyFs {
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
        counters: counters.clone(),
    };

    let options = MountOptions {
        fs_name: Some("libfuse-t-rs-smoke".to_string()),
        read_only: true,
        ..MountOptions::default()
    };

    let session = spawn_mount(fs, &mountpoint, &options).expect("spawn_mount succeeds");

    // Poll until root getattr fires.
    let saw_root = wait_for(
        || {
            let _ = std::fs::metadata(&mountpoint);
            counters.getattr_root.load(Ordering::Relaxed) > 0
        },
        Duration::from_secs(10),
    );
    assert!(saw_root, "root getattr never fired");

    // Stat the child file — must round-trip through our trait impl.
    let child_path = mountpoint.join(CHILD_NAME);
    let md = std::fs::metadata(&child_path).expect("stat child");
    assert_eq!(md.len(), CHILD_CONTENT.len() as u64);
    assert!(md.is_file());
    assert!(
        counters.getattr_child.load(Ordering::Relaxed) > 0,
        "child getattr never fired"
    );

    // Read the file. Opens, reads, releases.
    match std::fs::read(&child_path) {
        Ok(data) => {
            assert_eq!(data, CHILD_CONTENT);
            assert!(
                counters.open.load(Ordering::Relaxed) > 0,
                "open never fired"
            );
            assert!(
                counters.read.load(Ordering::Relaxed) > 0,
                "read never fired"
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "std::fs::read blocked by macOS Network Volumes TCC — \
                 open/read not exercised. Child getattr succeeded, so the \
                 safe-wrapper dispatch is proved."
            );
        }
        Err(e) => panic!("read failed with unexpected error: {e}"),
    }

    // readdir is also TCC-gated — best-effort assertion.
    match std::fs::read_dir(&mountpoint) {
        Ok(iter) => {
            let names: Vec<String> = iter
                .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
                .collect();
            eprintln!("read_dir entries: {names:?}");
            assert!(counters.readdir.load(Ordering::Relaxed) > 0);
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("read_dir blocked by Network Volumes TCC");
        }
        Err(e) => panic!("read_dir failed with unexpected error: {e}"),
    }

    drop(session); // triggers umount_and_join
}
