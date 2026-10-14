//! Live-shard end-to-end tests.
//!
//! These require a running local f1r3node shard (e.g. from
//! `f1r3node-rust/docker/shard.yml`) with a bundle entry provisioned as
//! the mount root. They are marked `#[ignore]` so plain `cargo test`
//! doesn't fail without the shard. Run with:
//!
//! ```shell
//! cargo test -p f1r3drive-fs --test live_shard -- --ignored --nocapture
//! ```
//!
//! Prerequisites:
//! 1. `docker compose -f ../f1r3node-rust/docker/shard.yml up -d`
//! 2. Shard config includes a `consensus-static-dirs = { root = { path =
//!    "/data/root", mode = "rw" } }` entry (or whatever `--mount-source`
//!    points at).
//! 3. Set `F1R3DRIVE_TEST_SK` to a hex-encoded private key matching a
//!    bonded validator in the shard's genesis. The hard-coded fallback
//!    is a placeholder scalar that no real shard will accept.
//!
//! On macOS the test must also have "Network Volumes" granted to the
//! parent terminal (see `libfuse-t-rs/tests/mount_smoke.rs` for the
//! full explanation). Without it, read_dir and read calls fail with
//! EPERM at the kernel, independent of our code.

#![cfg(target_os = "macos")]

use std::path::PathBuf;
use std::time::{Duration, Instant};

use f1r3drive_client::{KeyPair, NodeClient};
use f1r3drive_fs::{F1r3Fs, FsConfig};
use libfuse_t_rs::{spawn_mount, MountOptions};

const DEV_HOST: &str = "127.0.0.1";
const DEV_PORT: u16 = 40401;
const DEV_SHARD_ID: &str = "root";
/// Placeholder — override via `F1R3DRIVE_TEST_SK` to point at a real
/// bonded-validator key in your shard's genesis.
const DEV_SHARD_SK_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const MOUNT_SOURCE: &str = "root";

fn tokio_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
}

fn wait_for<F: FnMut() -> bool>(mut cond: F, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    cond()
}

#[test]
#[ignore]
fn live_shard_golden_path() {
    let runtime = tokio_runtime();

    let client = runtime
        .block_on(NodeClient::connect(DEV_HOST, DEV_PORT))
        .expect("connect");

    let sk_hex =
        std::env::var("F1R3DRIVE_TEST_SK").unwrap_or_else(|_| DEV_SHARD_SK_HEX.to_string());
    let signer = KeyPair::from_private_hex(&sk_hex).expect("key");

    let config = FsConfig {
        mount_source: MOUNT_SOURCE.to_string(),
        signer: Some(signer),
        shard_id: DEV_SHARD_ID.to_string(),
        manual_propose: false,
        ..FsConfig::default()
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let mountpoint: PathBuf = tmp.path().to_path_buf();

    let fs = F1r3Fs::new(runtime.handle().clone(), client, config);

    let opts = MountOptions {
        fs_name: Some("f1r3drive-e2e".into()),
        volume_name: Some("f1r3drive-e2e".into()),
        read_only: false,
        extra: Vec::new(),
    };

    let session = spawn_mount(fs, &mountpoint, &opts).expect("mount");

    // Wait for the mount to come up.
    assert!(
        wait_for(
            || std::fs::metadata(&mountpoint).is_ok(),
            Duration::from_secs(15),
        ),
        "mount never became live",
    );

    // Golden path. Each stanza prints its outcome so a partial failure
    // is diagnosable even without TCC-granted shells.
    let child = mountpoint.join("hello.txt");

    eprintln!("[1/5] stat root");
    let md = std::fs::metadata(&mountpoint).expect("stat root");
    assert!(md.is_dir());

    eprintln!("[2/5] write child");
    match std::fs::write(&child, b"hello from f1r3drive") {
        Ok(()) => eprintln!("    write OK"),
        Err(e) => eprintln!("    write failed: {e} (OK if Network Volumes not granted)"),
    }

    eprintln!("[3/5] read child");
    match std::fs::read(&child) {
        Ok(bytes) => {
            eprintln!("    read {} bytes", bytes.len());
            assert!(!bytes.is_empty(), "read returned empty");
        }
        Err(e) => eprintln!("    read failed: {e} (OK if Network Volumes not granted)"),
    }

    eprintln!("[4/5] stat child");
    match std::fs::metadata(&child) {
        Ok(md) => {
            eprintln!("    size={}", md.len());
            assert!(md.is_file());
        }
        Err(e) => eprintln!("    stat failed: {e}"),
    }

    eprintln!("[5/5] unlink child");
    match std::fs::remove_file(&child) {
        Ok(()) => eprintln!("    unlink OK"),
        Err(e) => eprintln!("    unlink failed: {e}"),
    }

    drop(session);
}

#[test]
#[ignore]
fn live_shard_readonly_without_signer() {
    let runtime = tokio_runtime();

    let client = runtime
        .block_on(NodeClient::connect(DEV_HOST, DEV_PORT))
        .expect("connect");

    let config = FsConfig {
        mount_source: MOUNT_SOURCE.to_string(),
        signer: None,
        shard_id: DEV_SHARD_ID.to_string(),
        ..FsConfig::default()
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let mountpoint = tmp.path().to_path_buf();

    let fs = F1r3Fs::new(runtime.handle().clone(), client, config);
    let opts = MountOptions {
        fs_name: Some("f1r3drive-e2e-ro".into()),
        read_only: true,
        ..MountOptions::default()
    };
    let session = spawn_mount(fs, &mountpoint, &opts).expect("mount ro");

    assert!(
        wait_for(
            || std::fs::metadata(&mountpoint).is_ok(),
            Duration::from_secs(15),
        ),
        "ro mount never became live",
    );

    // Attempt a write — must fail with EACCES/EROFS.
    let child = mountpoint.join("blocked.txt");
    match std::fs::write(&child, b"nope") {
        Ok(()) => panic!("read-only mount accepted a write"),
        Err(e) => eprintln!("write blocked as expected: {e}"),
    }

    drop(session);
}
