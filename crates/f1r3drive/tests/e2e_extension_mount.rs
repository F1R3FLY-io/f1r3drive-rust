//! End-to-end integration tests for `--mount-mode=extension`.
//!
//! Each test spawns a fresh daemon via `DaemonFixture::spawn_extension`
//! and exercises the ADR-0002 mount surface through `std::fs`,
//! asserting kernel-visible behaviour (not Rust-side struct state).
//! The fixture uses `InMemoryBlobStore` + no `--chain-factory`, so
//! these tests don't need a running shard and don't talk to a node
//! for content ops. Shard-side flows are already covered by
//! `e2e_paid_transfer.rs`.
//!
//! All tests `#[ignore]`-gated because they still need the node
//! reachable (the daemon's startup pokes it for status). Bring up
//! `docker/standalone.yml` first; see `tests/common/mod.rs` for the
//! same pattern used by `e2e_balance.rs` + `e2e_mount.rs`.

mod common;

use std::fs;

/// Hex pubkey → mounted-root-level directory name. Just a readability
/// alias; the daemon serves the identity.pub contents verbatim.
fn own_folder(fx: &common::DaemonFixture) -> std::path::PathBuf {
    fx.mountpoint.join(fx.own_pubkey_hex())
}

#[test]
#[ignore = "needs a running f1r3node for daemon startup"]
fn root_readdir_shows_the_owners_pubkey_folder() {
    skip_if_no_node!();
    let fx = common::DaemonFixture::spawn_extension();
    skip_if_tcc_blocked!(&fx);

    let own = fx.own_pubkey_hex();
    let entries: Vec<String> = fs::read_dir(&fx.mountpoint)
        .expect("read_dir mountpoint")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert!(
        entries.contains(&own),
        "root should contain owner's pubkey folder {own}; got {entries:?}"
    );
}

#[test]
#[ignore = "needs a running f1r3node for daemon startup"]
fn own_folder_contains_tokens_and_paid_transfer() {
    skip_if_no_node!();
    let fx = common::DaemonFixture::spawn_extension();
    skip_if_tcc_blocked!(&fx);

    let entries: Vec<String> = fs::read_dir(own_folder(&fx))
        .expect("read_dir own folder")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert!(entries.contains(&".tokens".to_string()), "{entries:?}");
    assert!(
        entries.contains(&"Paid transfer".to_string()),
        "{entries:?}"
    );
}

#[test]
#[ignore = "needs a running f1r3node for daemon startup"]
fn create_write_read_round_trips_through_fuse() {
    skip_if_no_node!();
    let fx = common::DaemonFixture::spawn_extension();
    skip_if_tcc_blocked!(&fx);

    let path = own_folder(&fx).join("notes.txt");
    fs::write(&path, b"hello, extension").expect("write");

    let readback = fs::read(&path).expect("read");
    assert_eq!(readback, b"hello, extension");

    // Readdir should now show the plaintext name.
    let entries: Vec<String> = fs::read_dir(own_folder(&fx))
        .expect("read_dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert!(
        entries.contains(&"notes.txt".to_string()),
        "readdir should surface the plaintext filename; got {entries:?}"
    );
}

#[test]
#[ignore = "needs a running f1r3node for daemon startup"]
fn rename_within_own_folder_preserves_content() {
    skip_if_no_node!();
    let fx = common::DaemonFixture::spawn_extension();
    skip_if_tcc_blocked!(&fx);

    let old = own_folder(&fx).join("original.md");
    let new = own_folder(&fx).join("renamed.md");
    fs::write(&old, b"same bytes").expect("write old");

    fs::rename(&old, &new).expect("rename");

    assert!(!old.exists(), "old path should be gone");
    assert_eq!(fs::read(&new).expect("read new"), b"same bytes");
}

#[test]
#[ignore = "needs a running f1r3node for daemon startup"]
fn unlink_own_file_removes_it_from_readdir() {
    skip_if_no_node!();
    let fx = common::DaemonFixture::spawn_extension();
    skip_if_tcc_blocked!(&fx);

    let path = own_folder(&fx).join("doomed.txt");
    fs::write(&path, b"ephemeral").expect("write");
    assert!(path.exists());

    fs::remove_file(&path).expect("unlink");

    assert!(!path.exists(), "unlinked file should not exist");
    let entries: Vec<String> = fs::read_dir(own_folder(&fx))
        .expect("read_dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert!(!entries.contains(&"doomed.txt".to_string()), "{entries:?}");
}

#[test]
#[ignore = "needs a running f1r3node for daemon startup"]
fn rmdir_on_own_folder_is_denied() {
    skip_if_no_node!();
    let fx = common::DaemonFixture::spawn_extension();
    skip_if_tcc_blocked!(&fx);

    let err = fs::remove_dir(own_folder(&fx)).expect_err("rmdir on own folder must fail");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::PermissionDenied,
        "expected EPERM, got {err:?}"
    );
}

#[test]
#[ignore = "needs a running f1r3node for daemon startup"]
fn drop_into_paid_transfer_mints_listing_visible_at_root() {
    skip_if_no_node!();
    let fx = common::DaemonFixture::spawn_extension();
    skip_if_tcc_blocked!(&fx);

    let drop_path = own_folder(&fx).join("Paid transfer").join("10REV-doc.txt");
    fs::write(&drop_path, b"for sale").expect("drop into Paid transfer");

    // Root readdir should now include a 32-char hex listing folder
    // next to the owner's pubkey folder.
    let own = fx.own_pubkey_hex();
    let listing_dirs: Vec<String> = fs::read_dir(&fx.mountpoint)
        .expect("read_dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n != &own)
        .collect();
    assert_eq!(
        listing_dirs.len(),
        1,
        "exactly one listing folder expected; got {listing_dirs:?}"
    );
    let id = &listing_dirs[0];
    assert_eq!(id.len(), 32, "listing folder should be 32-char hex");
    assert!(id.chars().all(|c| c.is_ascii_hexdigit()));

    // The listing exposes a `.info` file whose contents are the
    // listing JSON. Not asserting the full JSON shape here — that's
    // covered by the fs-crate unit tests — just that the file is
    // reachable through the mount.
    let info = fx.mountpoint.join(id).join(".info");
    let bytes = fs::read(&info).expect("read .info");
    assert!(!bytes.is_empty(), ".info should carry listing metadata");
}

#[test]
#[ignore = "needs a running f1r3node for daemon startup"]
fn owner_can_rmdir_their_own_listing() {
    skip_if_no_node!();
    let fx = common::DaemonFixture::spawn_extension();
    skip_if_tcc_blocked!(&fx);

    // Mint a listing.
    let drop_path = own_folder(&fx).join("Paid transfer").join("5REV-draft.txt");
    fs::write(&drop_path, b"wip").expect("drop into Paid transfer");

    let own = fx.own_pubkey_hex();
    let id = fs::read_dir(&fx.mountpoint)
        .expect("read_dir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().to_string())
        .find(|n| n != &own)
        .expect("listing id");

    // rmdir /<id> → should succeed on the local-only path.
    fs::remove_dir(fx.mountpoint.join(&id)).expect("rmdir listing");

    let remaining: Vec<String> = fs::read_dir(&fx.mountpoint)
        .expect("read_dir after rmdir")
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    assert_eq!(
        remaining,
        vec![own],
        "only the owner's pubkey folder should remain"
    );
}
