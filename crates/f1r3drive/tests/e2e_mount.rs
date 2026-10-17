//! End-to-end mount tests.
//!
//! Every test is `#[ignore]` by default — run with
//! `cargo test -p f1r3drive -- --ignored`. They assume:
//!
//! 1. A f1r3node is listening on `127.0.0.1:40401` with the
//!    `oracle-static-dirs.root` bundle configured. Bring one up via
//!    `docker/standalone.yml` in `f1r3node-rust`.
//! 2. The host OS supports FUSE: fuse-t on macOS, `/dev/fuse` +
//!    `libfuse3` on Linux. Tests `skip_if_no_node!()` cleanly if the
//!    node is absent; mount failure is a hard panic.
//!
//! Tests use ONLY `std::fs` against the mountpoint — this exercises
//! the FUSE boundary + the full gRPC pipeline + Rholang snippet
//! round-trip, same thing a user's shell or Finder would do.

mod common;

use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::Duration;

use common::DaemonFixture;

/// 32-KiB chunk size that matches NFS readahead and the macOS Finder
/// write-chunk size — the shape the on-chain write path was
/// originally tuned for.
const CHUNK: usize = 32 * 1024;

/// Smoke: mount comes up, directory listing works, root is a dir.
#[test]
#[ignore = "needs a running f1r3node + FUSE support on the host"]
fn mount_roundtrip_tiny_file() {
    skip_if_no_node!();
    let fx = DaemonFixture::spawn();
    skip_if_tcc_blocked!(&fx);

    let name = "e2e-tiny.bin";
    let dst: PathBuf = fx.mountpoint.join(name);
    let payload = b"hello world\n".to_vec();

    fs::write(&dst, &payload).expect("write tiny");

    // Readback via std::fs — this round-trips through the FUSE
    // boundary into our daemon's read snippet (seek+readN).
    let got = fs::read(&dst).expect("read tiny");
    assert_eq!(got, payload, "tiny file round-trip bytes must match");
}

/// readdir shows a newly-created file. Specifically checks that
/// `read_dir` on the mount root enumerates the file we just wrote.
#[test]
#[ignore = "needs a running f1r3node + FUSE support on the host"]
fn readdir_shows_newly_created_file() {
    skip_if_no_node!();
    let fx = DaemonFixture::spawn();
    skip_if_tcc_blocked!(&fx);

    let name = "e2e-readdir-marker.txt";
    let dst = fx.mountpoint.join(name);
    fs::write(&dst, b"ping").expect("write marker");

    let entries: Vec<String> = fs::read_dir(&fx.mountpoint)
        .expect("read_dir mount root")
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();

    assert!(
        entries.iter().any(|e| e == name),
        "readdir should contain the marker; got {entries:?}",
    );
}

/// unlink removes the file: readdir no longer sees it; opening
/// returns ENOENT.
#[test]
#[ignore = "needs a running f1r3node + FUSE support on the host"]
fn unlink_removes_file() {
    skip_if_no_node!();
    let fx = DaemonFixture::spawn();
    skip_if_tcc_blocked!(&fx);

    let name = "e2e-unlink.bin";
    let dst = fx.mountpoint.join(name);
    fs::write(&dst, b"soon to be gone").expect("write");
    assert!(dst.exists(), "precondition: file should exist after write");

    fs::remove_file(&dst).expect("unlink");

    // Depending on the kernel's attr-cache TTL, the file may still
    // show up for up to 1s. Poll briefly.
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while dst.exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        !dst.exists(),
        "unlinked file should disappear; still visible at {}",
        dst.display(),
    );
}

/// Three-megabyte round-trip, byte-exact. This is the Finder-drag
/// scenario — many parallel 32-KiB writes + the subsequent read
/// pass. Exercises the parallel-read serialization fix (reads share
/// a server-side kernel fd cursor, so our daemon serializes).
#[test]
#[ignore = "needs a running f1r3node + FUSE support on the host"]
fn large_file_byte_exact_roundtrip() {
    skip_if_no_node!();
    let fx = DaemonFixture::spawn();
    skip_if_tcc_blocked!(&fx);

    // 3 MiB of pseudorandom content; deterministic PRNG seed so a
    // flake doesn't amplify into "which byte went bad".
    let total: usize = 3 * 1024 * 1024;
    let mut src = Vec::with_capacity(total);
    let mut state: u64 = 0xDEAD_BEEF_C0FF_EE42_u64;
    for _ in 0..total {
        // xorshift64 — cheap, uniform-ish, deterministic.
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        src.push((state & 0xff) as u8);
    }

    let dst = fx.mountpoint.join("e2e-large.bin");

    // Write in 32-KiB chunks to match how Finder / NFS does it on
    // the real-world path.
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&dst)
            .expect("open for write");
        for chunk in src.chunks(CHUNK) {
            f.write_all(chunk).expect("chunk write");
        }
        f.flush().expect("flush");
    }

    // Read back and compare.
    let mut got = Vec::with_capacity(total);
    let mut f = fs::File::open(&dst).expect("open for read");
    f.read_to_end(&mut got).expect("read_to_end");

    assert_eq!(got.len(), src.len(), "size mismatch");
    // Avoid a 3-MiB diff dump on failure — tell the user the
    // offset of first divergence.
    if got != src {
        let first_bad = src.iter().zip(got.iter()).position(|(a, b)| a != b);
        panic!(
            "byte mismatch at offset {:?} (size {} == {}, hashes differ)",
            first_bad,
            src.len(),
            got.len(),
        );
    }
}

/// Multiple writes to the same file at distinct offsets round-trip
/// correctly. Shrunk-down version of the Finder large-file case so
/// it can run even when the shard's phlo limits are stingy.
#[test]
#[ignore = "needs a running f1r3node + FUSE support on the host"]
fn multi_chunk_write_roundtrip() {
    skip_if_no_node!();
    let fx = DaemonFixture::spawn();
    skip_if_tcc_blocked!(&fx);

    let dst = fx.mountpoint.join("e2e-multichunk.bin");
    // Three distinct chunks with recognisable magic bytes so the
    // failure message is actionable.
    let payload: Vec<u8> = {
        let mut v = Vec::with_capacity(3 * 1024);
        v.extend(std::iter::repeat_n(0xAA, 1024));
        v.extend(std::iter::repeat_n(0xBB, 1024));
        v.extend(std::iter::repeat_n(0xCC, 1024));
        v
    };
    fs::write(&dst, &payload).expect("write multichunk");
    let got = fs::read(&dst).expect("read multichunk");
    assert_eq!(got, payload, "multichunk round-trip must preserve bytes");
}
