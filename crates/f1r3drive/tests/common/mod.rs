//! Test harness for the e2e mount integration tests.
//!
//! Shared across the macOS (fuse-t) and Linux (fuser) backends:
//!
//! - [`node_available`] probes the local f1r3node on 127.0.0.1:40401
//!   via a gRPC status call. The tests use this to **skip** cleanly
//!   when no node is up — e2e runs are opt-in anyway (every test is
//!   `#[ignore]`), so missing-node is a precondition miss rather than
//!   a bug.
//! - [`DaemonFixture`] spawns the compiled `f1r3drive` binary as a
//!   subprocess, polls until the mount shows up in the kernel's
//!   mount table, and tears down (SIGTERM + force-unmount) on `Drop`.
//! - [`write_fresh_key`] drops a one-off secp256k1 keyfile under
//!   `TMPDIR`; the daemon loads it via `--key-file`.
//!
//! None of this touches the Rholang / Fs-agent machinery directly —
//! the tests exercise ONLY the FUSE boundary via `std::fs`.

#![allow(dead_code)] // Each test file picks and chooses helpers.

use std::fs;
use std::io::{Read as _, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Default node endpoint — matches `docker/standalone.yml`'s exposed
/// external gRPC port. Override with `F1R3DRIVE_NODE_HOST` /
/// `F1R3DRIVE_NODE_PORT` env vars when the node lives on a different
/// address (e.g. a container on a non-default bridge network).
const DEFAULT_NODE_HOST: &str = "127.0.0.1";
const DEFAULT_NODE_PORT: u16 = 40401;

pub fn node_host() -> String {
    std::env::var("F1R3DRIVE_NODE_HOST").unwrap_or_else(|_| DEFAULT_NODE_HOST.into())
}

pub fn node_port() -> u16 {
    std::env::var("F1R3DRIVE_NODE_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_NODE_PORT)
}

/// How long to wait for the mount to appear after spawning the
/// daemon. fuse-t on macOS can take several seconds to clear a
/// stale go-nfsv4 session; fuser on Linux is near-instant.
const MOUNT_READY_TIMEOUT: Duration = Duration::from_secs(30);
/// Polling interval while waiting for mount readiness.
const MOUNT_POLL: Duration = Duration::from_millis(250);

/// Returns `true` if a node is listening on the configured endpoint
/// and accepts a TCP connection within the probe timeout. Any failure
/// (connection refused, timeout, bad address) → `false`.
pub fn node_available() -> bool {
    // Minimal TCP probe — if nothing's on the port, bail cheaply.
    // We don't speak gRPC here; the daemon spawn will fail loudly
    // with a connection error if the port's live but the service
    // isn't speaking the right protocol.
    use std::net::TcpStream;
    use std::net::ToSocketAddrs;
    let addrs = match format!("{}:{}", node_host(), node_port()).to_socket_addrs() {
        Ok(a) => a,
        Err(_) => return false,
    };
    for addr in addrs {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok() {
            return true;
        }
    }
    false
}

/// Skip-if-no-node macro. Call at the top of every e2e test; prints
/// a note so humans running `cargo test -- --ignored` see why a
/// test came back `ok` without doing anything.
#[macro_export]
macro_rules! skip_if_no_node {
    () => {
        if !$crate::common::node_available() {
            eprintln!(
                "skipping e2e test: no node reachable on {}:{} \
                 (bring up `docker/standalone.yml` first)",
                $crate::common::node_host(),
                $crate::common::node_port(),
            );
            return;
        }
    };
}

/// Skip the test if a probe write to the fixture's mountpoint
/// returns `EPERM`. On macOS, `std::fs::write` into an NFS-backed
/// mount (which fuse-t presents to the kernel) is TCC-gated under
/// "Network Volumes"; the test runner inherits the Terminal's
/// permission bits, so unattended CI and plain shells without that
/// permission granted will fail every write with EPERM. Rather
/// than painting that as a product bug, skip explicitly with a
/// pointer at the setting that needs flipping.
pub fn skip_if_tcc_blocked(fx: &DaemonFixture) -> bool {
    let probe = fx.mountpoint.join(".e2e-tcc-probe");
    match fs::write(&probe, b"") {
        Ok(()) => {
            let _ = fs::remove_file(&probe);
            false
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!(
                "skipping e2e test: writes to the FUSE mount at {} \
                 return EPERM — on macOS grant Terminal (or whatever \
                 is running `cargo test`) the \"Network Volumes\" \
                 permission under System Settings → Privacy & \
                 Security → Files and Folders. Linux CI should not \
                 hit this path.",
                fx.mountpoint.display(),
            );
            true
        }
        Err(e) => panic!("TCC probe failed with unexpected error: {e}"),
    }
}

#[macro_export]
macro_rules! skip_if_tcc_blocked {
    ($fx:expr) => {
        if $crate::common::skip_if_tcc_blocked($fx) {
            return;
        }
    };
}

/// Standalone-dev validator's secp256k1 private key (hex). The
/// matching REV address is in `f1r3node-rust/docker/genesis/
/// standalone-wallets.txt` and is funded with 50 QV REV at genesis,
/// which is what lets our mutating deploys pay their pre-charge.
/// Any arbitrary key would admit + get included in a block but then
/// fail `pre-charge evaluation` with "Insufficient funds", silently
/// no-op'ing the Rholang mutation.
const STANDALONE_DEV_FUNDED_KEY: &str =
    "5f668a7ee96d944a4494cc947e4005e172d7ab3461ee5538f1f2a45a835e9657";

/// Resolve the signing-key hex to use for the daemon the fixture
/// spawns. Checks `F1R3DRIVE_SIGNING_KEY` first (hex, with or without
/// `0x` prefix) so a differently-provisioned shard can override;
/// otherwise defaults to the standalone-dev validator above.
pub fn signing_key_hex() -> String {
    std::env::var("F1R3DRIVE_SIGNING_KEY").unwrap_or_else(|_| STANDALONE_DEV_FUNDED_KEY.into())
}

/// 32-byte secp256k1 private key, written to a temp file as 64 hex
/// chars. Caller owns the path; delete when done.
pub fn write_fresh_key() -> PathBuf {
    let key_hex = signing_key_hex();
    let dir = std::env::temp_dir();
    let path = dir.join(format!("f1r3drive-e2e-key-{}.hex", std::process::id()));
    let mut f = fs::File::create(&path).expect("create key file");
    f.write_all(key_hex.as_bytes()).expect("write key");
    path
}

/// A spawned `f1r3drive` daemon + mountpoint. Dropping the fixture
/// SIGTERMs the daemon and force-unmounts the mountpoint (whichever
/// side-effect sticks on the host OS). Both are best-effort —
/// orphan mounts don't fail the test, just leave a note.
pub struct DaemonFixture {
    /// Where the mount lives. Owned by the fixture; removed on drop.
    pub mountpoint: PathBuf,
    pub key_path: PathBuf,
    /// `None` once the fixture has been torn down (via Drop).
    child: Option<Child>,
    /// Captured daemon stderr. On a panicking Drop (i.e. the test
    /// failed), we spill this to the test runner's stderr so
    /// `cargo test` output explains *why* the mount misbehaved.
    stderr_buf: Arc<Mutex<Vec<u8>>>,
    stderr_reader: Option<JoinHandle<()>>,
    /// Keep this around so the tempdir only cleans up at the end.
    _mount_parent: tempfile::TempDir,
}

impl DaemonFixture {
    /// Spawn a daemon, wait for the mount to show up, return a
    /// fixture with a readable `.mountpoint`.
    pub fn spawn() -> Self {
        let parent = tempfile::tempdir().expect("tempdir");
        let mountpoint = parent.path().join("mnt");
        fs::create_dir(&mountpoint).expect("mkdir mountpoint");

        let key_path = write_fresh_key();

        // `CARGO_BIN_EXE_<name>` is set by cargo for the current
        // crate's binary — our tests live in `f1r3drive`, so this
        // resolves to the just-built daemon.
        let bin = env!("CARGO_BIN_EXE_f1r3drive");

        let mut cmd = Command::new(bin);
        cmd.arg("--host")
            .arg(node_host())
            .arg("--port")
            .arg(node_port().to_string())
            .arg("--mount-source")
            .arg("root")
            .arg("--key-file")
            .arg(&key_path)
            .arg("--debug")
            .arg("--volume-name")
            .arg("f1r3drive-e2e")
            .arg(&mountpoint);
        cmd.stdout(Stdio::null()).stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("spawn daemon");

        // Drain stderr continuously into an in-memory buffer. If we
        // skip this, the pipe's kernel buffer fills (~64 KiB on
        // Linux) and the daemon wedges on its next log write. The
        // buffer gets dumped by Drop if the test panics.
        let stderr_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let stderr_reader = child.stderr.take().map(|mut pipe| {
            let buf = Arc::clone(&stderr_buf);
            thread::spawn(move || {
                let mut chunk = [0u8; 4096];
                loop {
                    match pipe.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => buf.lock().unwrap().extend_from_slice(&chunk[..n]),
                        Err(_) => break,
                    }
                }
            })
        });

        let fx = Self {
            mountpoint,
            key_path,
            child: Some(child),
            stderr_buf,
            stderr_reader,
            _mount_parent: parent,
        };

        fx.wait_for_mount();
        fx
    }

    /// Dump everything we've captured from the daemon's stderr so far
    /// to the test runner's stderr. Called from Drop when the test
    /// is panicking; test authors can also call it manually to peek.
    pub fn dump_daemon_stderr(&self) {
        let buf = self.stderr_buf.lock().unwrap();
        if buf.is_empty() {
            eprintln!("--- daemon stderr (empty) ---");
            return;
        }
        eprintln!("--- daemon stderr ({} bytes) ---", buf.len());
        eprintln!("{}", String::from_utf8_lossy(&buf));
        eprintln!("--- end daemon stderr ---");
    }

    /// Block until the mount appears in the kernel's mount table or
    /// the timeout fires. Panics on timeout — the test author's
    /// intent is "mount or bust".
    fn wait_for_mount(&self) {
        let start = Instant::now();
        while start.elapsed() < MOUNT_READY_TIMEOUT {
            if is_mounted(&self.mountpoint) {
                // Give the daemon one more beat to finish any
                // readdir pre-warm — e2e tests do an immediate
                // `std::fs::read_dir` and we don't want to race.
                thread::sleep(Duration::from_millis(100));
                return;
            }
            thread::sleep(MOUNT_POLL);
        }
        panic!(
            "mount did not appear at {} within {:?}",
            self.mountpoint.display(),
            MOUNT_READY_TIMEOUT,
        );
    }
}

impl Drop for DaemonFixture {
    fn drop(&mut self) {
        let panicking = thread::panicking();
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(h) = self.stderr_reader.take() {
            let _ = h.join();
        }
        if panicking {
            self.dump_daemon_stderr();
        }
        // Unmount is best-effort — the daemon's own exit may have
        // already cleaned up. Try both OSes' tools.
        let mp = self.mountpoint.to_string_lossy();
        #[cfg(target_os = "macos")]
        {
            let _ = Command::new("diskutil")
                .args(["unmount", "force", mp.as_ref()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        #[cfg(target_os = "linux")]
        {
            let _ = Command::new("fusermount3")
                .args(["-u", mp.as_ref()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = Command::new("umount")
                .args([mp.as_ref()])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = fs::remove_file(&self.key_path);
    }
}

/// Check whether `path` is a mountpoint. Uses `/proc/self/mounts` on
/// Linux and the `mount` command on macOS — avoiding `statfs`
/// because its `f_type` field is OS-flavored.
pub fn is_mounted(path: &Path) -> bool {
    let path_str = path.to_string_lossy();

    #[cfg(target_os = "linux")]
    {
        if let Ok(mounts) = fs::read_to_string("/proc/self/mounts") {
            for line in mounts.lines() {
                // Format: `<src> <mountpoint> <fstype> <opts> ...`
                if let Some(mp) = line.split_whitespace().nth(1) {
                    if mp == path_str {
                        return true;
                    }
                }
            }
        }
        false
    }

    #[cfg(target_os = "macos")]
    {
        let out = Command::new("mount").output();
        let Ok(out) = out else {
            return false;
        };
        let stdout = String::from_utf8_lossy(&out.stdout);
        // `mount` output format: `<src> on <mountpoint> (<fstype>, …)`.
        // The macOS mountpoint is the `/private/tmp/…` realpath so we
        // compare against the canonicalized mountpoint.
        let canonical = fs::canonicalize(path)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| path_str.into_owned());
        for line in stdout.lines() {
            if line.contains(&format!(" on {canonical} ")) {
                return true;
            }
        }
        false
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = path_str;
        false
    }
}
