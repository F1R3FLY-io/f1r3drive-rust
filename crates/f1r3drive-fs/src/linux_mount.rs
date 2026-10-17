//! Linux mount backend.
//!
//! `fuser` exposes a `/dev/fuse` kernel-protocol `Filesystem` trait
//! whose callbacks are **inode-indexed**, not path-indexed. Our
//! shared behavior ([`crate::F1r3Fs`] implementing
//! [`libfuse_t_rs::Filesystem`]) is path-indexed because that's what
//! both the libfuse-t high-level C API and the on-chain Fs agent
//! speak natively. This module is the bridge.
//!
//! # Inode allocator
//!
//! Monotonic 64-bit counter starting at `FUSE_ROOT_ID + 1 = 2`
//! (the root is pinned at `1` per the FUSE convention). Each
//! unique path we observe (`lookup`, `mkdir`, `create`, `rename`)
//! gets its own inode; a `RwLock<HashMap<u64, PathBuf>>` maps the
//! inode back when the kernel references it. The reverse map
//! (`HashMap<PathBuf, u64>`) coalesces repeated `lookup`s on the
//! same name so the kernel's dcache attribute invalidation lines up
//! across calls.
//!
//! Allocations are never recycled during the mount's lifetime, so an
//! open-then-unlink'd handle keeps resolving to its original path
//! (which is also how `libfuse-t-rs` behaves). Memory grows with
//! the number of distinct paths ever observed — bounded by the real
//! filesystem's cardinality.
//!
//! # Attribute translation
//!
//! [`libfuse_t_rs::FileAttr`] already carries everything `fuser`
//! needs; [`attr_to_fuser`] below walks the fields in order and emits
//! a `fuser::FileAttr`. Timestamps round down to seconds — matches
//! the on-chain stat records' granularity.
//!
//! # Caveats vs. the macOS backend
//!
//! * `statfs` isn't surfaced through fuser's trait today — the
//!   kernel synthesises a reasonable default. If Finder-style
//!   free-space probes matter on Linux we'll add it later.
//! * `fuser 0.14` doesn't yet support `allow_other` under rootless
//!   containers; the default is "only the mount owner can see the
//!   mount". That's fine for `podman run --device /dev/fuse` or a
//!   bare-metal user mount.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

use fuser::{
    FileAttr as FuserAttr, FileType, Filesystem as FuserFilesystem, MountOption, ReplyAttr,
    ReplyCreate, ReplyData, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyWrite, Request,
};
use libfuse_t_rs::{
    DirEntry, FileAttr as InnerAttr, FileKind, Filesystem as InnerFilesystem, FsError,
};

use crate::F1r3Fs;

/// User-facing mount options for the Linux backend.
#[derive(Debug, Clone, Default)]
pub struct LinuxMountOptions {
    /// `-o fsname=...`; defaults to `"f1r3drive"` if unset.
    pub fs_name: Option<String>,
    /// Mount read-only.
    pub read_only: bool,
    /// Allow other users on the host to see the mount (requires
    /// `user_allow_other` in `/etc/fuse.conf` on most distros).
    pub allow_other: bool,
    /// Any additional raw `-o <opt>` strings to pass through.
    pub extra: Vec<String>,
}

/// Attribute TTL exposed to the kernel. The on-chain state only
/// changes block-by-block (seconds granularity in practice), so a
/// one-second TTL keeps the kernel's attribute cache aligned without
/// pinning stale data.
const ATTR_TTL: Duration = Duration::from_secs(1);
/// Entry (directory-lookup) TTL. Mirrors `ATTR_TTL`.
const ENTRY_TTL: Duration = Duration::from_secs(1);
/// Classic FUSE root inode. Allocated to `/` at construction.
const ROOT_INO: u64 = fuser::FUSE_ROOT_ID;

/// Mount `fs` at `mountpoint` and block until the kernel unmounts
/// (SIGINT, `fusermount3 -u`, etc.). Returns on clean unmount.
pub fn mount(fs: F1r3Fs, mountpoint: &Path, opts: &LinuxMountOptions) -> std::io::Result<()> {
    let adapter = PathAdapter::new(fs);

    let mut mount_opts = Vec::with_capacity(8);
    mount_opts.push(MountOption::FSName(
        opts.fs_name.clone().unwrap_or_else(|| "f1r3drive".into()),
    ));
    mount_opts.push(MountOption::Subtype("f1r3drive".into()));
    mount_opts.push(MountOption::DefaultPermissions);
    if opts.read_only {
        mount_opts.push(MountOption::RO);
    } else {
        mount_opts.push(MountOption::RW);
    }
    if opts.allow_other {
        mount_opts.push(MountOption::AllowOther);
    }
    for e in &opts.extra {
        mount_opts.push(MountOption::CUSTOM(e.clone()));
    }

    fuser::mount2(adapter, mountpoint, &mount_opts)
}

/// Thin inode↔path adapter wrapping a `libfuse_t_rs::Filesystem`.
struct PathAdapter<F: InnerFilesystem> {
    inner: F,
    /// Monotonic allocator; next free inode value.
    next_ino: AtomicU64,
    /// `ino → path` (what the kernel hands us vs. what we hand the
    /// shared trait).
    by_ino: RwLock<HashMap<u64, PathBuf>>,
    /// Reverse map so a lookup of the same name repeatedly collapses
    /// onto the same inode — critical for the kernel's dcache.
    by_path: RwLock<HashMap<PathBuf, u64>>,
}

impl<F: InnerFilesystem> PathAdapter<F> {
    fn new(inner: F) -> Self {
        let mut by_ino = HashMap::new();
        by_ino.insert(ROOT_INO, PathBuf::from("/"));
        let mut by_path = HashMap::new();
        by_path.insert(PathBuf::from("/"), ROOT_INO);
        Self {
            inner,
            next_ino: AtomicU64::new(ROOT_INO + 1),
            by_ino: RwLock::new(by_ino),
            by_path: RwLock::new(by_path),
        }
    }

    /// Look up the path currently bound to `ino`. `None` only if
    /// the kernel referenced an inode we never allocated — treat as
    /// ENOENT at the call site.
    fn path_of(&self, ino: u64) -> Option<PathBuf> {
        self.by_ino.read().ok()?.get(&ino).cloned()
    }

    /// Intern `path`: returns the existing inode if we've seen it,
    /// else allocates a fresh one.
    fn intern(&self, path: &Path) -> u64 {
        if let Ok(by_path) = self.by_path.read() {
            if let Some(&ino) = by_path.get(path) {
                return ino;
            }
        }
        // Rare path: fall through to the write-lock allocator.
        let mut by_path = self.by_path.write().expect("by_path lock poisoned");
        if let Some(&ino) = by_path.get(path) {
            return ino;
        }
        let ino = self.next_ino.fetch_add(1, Ordering::Relaxed);
        by_path.insert(path.to_path_buf(), ino);
        self.by_ino
            .write()
            .expect("by_ino lock poisoned")
            .insert(ino, path.to_path_buf());
        ino
    }

    /// Rebind an existing path to a new path (rename). We keep the
    /// inode stable so open handles survive the rename, matching
    /// POSIX. If `from` wasn't interned, this is a no-op.
    fn rename_binding(&self, from: &Path, to: &Path) {
        let mut by_path = self.by_path.write().expect("by_path lock poisoned");
        let mut by_ino = self.by_ino.write().expect("by_ino lock poisoned");
        if let Some(ino) = by_path.remove(from) {
            by_path.insert(to.to_path_buf(), ino);
            by_ino.insert(ino, to.to_path_buf());
        }
    }

    /// Drop a `path`'s inode binding (called on unlink / rmdir).
    /// The kernel is responsible for not calling us with it again.
    fn forget_path(&self, path: &Path) {
        let mut by_path = self.by_path.write().expect("by_path lock poisoned");
        let mut by_ino = self.by_ino.write().expect("by_ino lock poisoned");
        if let Some(ino) = by_path.remove(path) {
            by_ino.remove(&ino);
        }
    }

    /// Build a child path by joining `name` under the parent at
    /// `parent_ino`. Returns `None` if the parent inode is unknown.
    /// `PathBuf::push` already handles the leading-slash case
    /// correctly on `/` (produces `/name`, not `//name`), so we don't
    /// need to branch on it.
    fn child_path(&self, parent_ino: u64, name: &OsStr) -> Option<PathBuf> {
        let parent = self.path_of(parent_ino)?;
        let name = name.to_str()?;
        let mut p = parent;
        p.push(name);
        Some(p)
    }
}

/// Convert the shared `FileAttr` into fuser's `FileAttr`. The inode
/// has to come from our interner — the shared trait doesn't know
/// about inodes.
fn attr_to_fuser(ino: u64, src: &InnerAttr) -> FuserAttr {
    FuserAttr {
        ino,
        size: src.size,
        blocks: src.blocks.unwrap_or_else(|| src.size.div_ceil(512)),
        atime: src.atime,
        mtime: src.mtime,
        ctime: src.ctime,
        crtime: SystemTime::UNIX_EPOCH,
        kind: kind_to_fuser(src.kind),
        perm: src.perm,
        nlink: src.nlink,
        uid: src.uid,
        gid: src.gid,
        rdev: 0,
        blksize: src.blksize,
        flags: 0,
    }
}

fn kind_to_fuser(k: FileKind) -> FileType {
    match k {
        FileKind::Directory => FileType::Directory,
        FileKind::Regular => FileType::RegularFile,
        FileKind::Other => FileType::RegularFile,
    }
}

fn errno(e: FsError) -> i32 {
    e.to_errno()
}

/// Build a fresh regular-file attribute for a just-created file.
/// The real stat payload comes back on the next on-chain `getattr`
/// once LFB catches up with the admit+propose; this is just enough
/// to populate `ReplyCreate`.
fn synthesize_regular_file(perm: u32) -> InnerAttr {
    InnerAttr {
        kind: FileKind::Regular,
        perm: perm as u16,
        size: 0,
        nlink: 1,
        uid: 0,
        gid: 0,
        atime: SystemTime::UNIX_EPOCH,
        mtime: SystemTime::UNIX_EPOCH,
        ctime: SystemTime::UNIX_EPOCH,
        blocks: None,
        blksize: 4096,
    }
}

/// Companion to [`synthesize_regular_file`] for `mkdir`.
fn synthesize_directory(perm: u32) -> InnerAttr {
    InnerAttr {
        kind: FileKind::Directory,
        perm: perm as u16,
        size: 0,
        nlink: 2,
        uid: 0,
        gid: 0,
        atime: SystemTime::UNIX_EPOCH,
        mtime: SystemTime::UNIX_EPOCH,
        ctime: SystemTime::UNIX_EPOCH,
        blocks: None,
        blksize: 4096,
    }
}

impl<F: InnerFilesystem + Send + Sync + 'static> FuserFilesystem for PathAdapter<F> {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let Some(path) = self.child_path(parent, name) else {
            reply.error(libc::ENOENT);
            return;
        };
        match self.inner.getattr(&path) {
            Ok(a) => {
                let ino = self.intern(&path);
                reply.entry(&ENTRY_TTL, &attr_to_fuser(ino, &a), 0);
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        let Some(path) = self.path_of(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        match self.inner.getattr(&path) {
            Ok(a) => reply.attr(&ATTR_TTL, &attr_to_fuser(ino, &a)),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let Some(path) = self.path_of(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        let entries: Vec<DirEntry> = match self.inner.readdir(&path) {
            Ok(v) => v,
            Err(e) => {
                reply.error(errno(e));
                return;
            }
        };
        // Synthesize `.` and `..` for POSIX, then stream entries.
        // fuser's `offset` is the cookie returned from the previous
        // call; we use positional indices.
        let mut emit = |idx: i64, child_ino: u64, kind: FileType, name: &str| {
            if idx <= offset {
                return false;
            }
            reply.add(child_ino, idx, kind, name)
        };
        let _ = emit(1, ino, FileType::Directory, ".");
        // Parent of root is root — fuser doesn't track it anyway.
        let parent_ino = if path == Path::new("/") {
            ino
        } else {
            path.parent()
                .and_then(|p| self.intern(p).into())
                .unwrap_or(ROOT_INO)
        };
        let _ = emit(2, parent_ino, FileType::Directory, "..");
        for (i, entry) in entries.into_iter().enumerate() {
            let child_path = {
                let mut p = path.clone();
                p.push(&entry.name);
                p
            };
            let child_ino = self.intern(&child_path);
            if emit(
                (i as i64) + 3,
                child_ino,
                kind_to_fuser(entry.kind),
                &entry.name,
            ) {
                break;
            }
        }
        reply.ok();
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: fuser::ReplyOpen) {
        let Some(path) = self.path_of(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        match self.inner.open(&path, 0) {
            Ok(_fh) => reply.opened(0, 0),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn release(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        _flags: i32,
        _lock_owner: Option<u64>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        let Some(path) = self.path_of(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        match self.inner.release(&path, 0) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let Some(path) = self.path_of(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        let off = offset.max(0) as u64;
        match self.inner.read(&path, off, size as usize, 0) {
            Ok(bytes) => reply.data(&bytes),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        let Some(path) = self.path_of(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        let off = offset.max(0) as u64;
        match self.inner.write(&path, off, data, 0) {
            Ok(n) => reply.written(n as u32),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn create(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let Some(path) = self.child_path(parent, name) else {
            reply.error(libc::ENOENT);
            return;
        };
        match self.inner.create(&path, mode, 0) {
            Ok(_fh) => {
                // fuser's `ReplyCreate` needs the attributes NOW, but
                // querying on-chain state immediately after a mutating
                // deploy races the LFB: `inner.create` returns as soon
                // as the block that admitted the deploy is proposed,
                // but `exploratory_deploy` reads post-state of the
                // Last Finalized Block, which may still trail by one.
                // Synthesize a zero-byte regular file attr — the real
                // size will show up on the next `getattr` after
                // finalization catches up. Matches how the macOS
                // backend behaves (libfuse-t just returns `0` from
                // `op_create` and refetches attrs lazily).
                let ino = self.intern(&path);
                let attr = synthesize_regular_file(mode & 0o7777);
                reply.created(&ENTRY_TTL, &attr_to_fuser(ino, &attr), 0, 0, 0);
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn mkdir(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let Some(path) = self.child_path(parent, name) else {
            reply.error(libc::ENOENT);
            return;
        };
        match self.inner.mkdir(&path, mode) {
            Ok(()) => {
                let ino = self.intern(&path);
                let attr = synthesize_directory(mode & 0o7777);
                reply.entry(&ENTRY_TTL, &attr_to_fuser(ino, &attr), 0);
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(path) = self.child_path(parent, name) else {
            reply.error(libc::ENOENT);
            return;
        };
        match self.inner.unlink(&path) {
            Ok(()) => {
                self.forget_path(&path);
                reply.ok();
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        let Some(path) = self.child_path(parent, name) else {
            reply.error(libc::ENOENT);
            return;
        };
        match self.inner.rmdir(&path) {
            Ok(()) => {
                self.forget_path(&path);
                reply.ok();
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        let (Some(from), Some(to)) = (
            self.child_path(parent, name),
            self.child_path(newparent, newname),
        ) else {
            reply.error(libc::ENOENT);
            return;
        };
        match self.inner.rename(&from, &to) {
            Ok(()) => {
                self.rename_binding(&from, &to);
                reply.ok();
            }
            Err(e) => reply.error(errno(e)),
        }
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        _uid: Option<u32>,
        _gid: Option<u32>,
        size: Option<u64>,
        _atime: Option<fuser::TimeOrNow>,
        _mtime: Option<fuser::TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let Some(path) = self.path_of(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        if let Some(new_size) = size {
            if let Err(e) = self.inner.truncate(&path, new_size) {
                reply.error(errno(e));
                return;
            }
        }
        if let Some(new_mode) = mode {
            if let Err(e) = self.inner.chmod(&path, new_mode) {
                reply.error(errno(e));
                return;
            }
        }
        match self.inner.getattr(&path) {
            Ok(a) => reply.attr(&ATTR_TTL, &attr_to_fuser(ino, &a)),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn flush(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        let Some(path) = self.path_of(ino) else {
            reply.error(libc::ENOENT);
            return;
        };
        match self.inner.flush(&path, 0) {
            Ok(()) => reply.ok(),
            Err(e) => reply.error(errno(e)),
        }
    }

    fn access(&mut self, _req: &Request<'_>, ino: u64, _mask: i32, reply: ReplyEmpty) {
        if self.path_of(ino).is_some() {
            reply.ok();
        } else {
            reply.error(libc::ENOENT);
        }
    }
}
