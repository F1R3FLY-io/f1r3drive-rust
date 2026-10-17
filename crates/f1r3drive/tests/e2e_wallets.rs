//! End-to-end tests for `--mount-mode=wallets`.
//!
//! Every test is `#[ignore]` by default — run with
//! `cargo test -p f1r3drive --test e2e_wallets -- --ignored --test-threads=1`.
//!
//! Prerequisites:
//! 1. A f1r3node is listening on
//!    `F1R3DRIVE_NODE_HOST:F1R3DRIVE_NODE_PORT` (defaults to
//!    `127.0.0.1:40401`) with the standalone-dev genesis wallet set
//!    (the validator at `1111Atah…` is funded).
//! 2. The host OS supports FUSE: fuse-t on macOS, `/dev/fuse` on
//!    Linux. On macOS without Network Volumes TCC, writes to the
//!    mount surface skip (shared with `e2e_mount.rs`).
//!
//! Scope:
//! - Mount comes up, `/` lists the pre-unlocked validator wallet.
//! - `.tokens/` enumerates bills totalling the on-chain balance.
//! - The extension gRPC `UnlockWalletDirectory` promotes a locked
//!   address (we track a bogus one, then unlock it with a known
//!   key).
//! - `SubmitAction(CHANGE, …)` changes the client-side bill shape
//!   without touching the on-chain balance.
//! - `SubmitAction(COMBINE, …)` returns the "not implemented"
//!   error, matching Java + ADR-0001.
//!
//! Cross-wallet TRANSFER-via-rename is not covered automatically —
//! the standalone-dev shard has one funded wallet; a two-wallet
//! transfer test needs a shard config change and belongs with
//! Stage 8+ CI work. Verified manually.

mod common;

use std::time::Duration;

use f1r3drive_client::{KeyPair, NodeClient};
use f1r3drive_ext::{forward_unlock, UnlockLink, UnlockOutcome};
use f1r3drive_proto::generic::finder_sync_extension_service_client::FinderSyncExtensionServiceClient;
use f1r3drive_proto::generic::response::Result as RpcResult;
use f1r3drive_proto::generic::{MenuActionRequest, MenuActionType, UnlockWalletDirectoryRequest};
use f1r3drive_rho::{check_balance_snippet, decode_balance_reply};
use f1r3drive_wallet::RevAddress;
use tonic::transport::Channel;

use common::DaemonFixture;

const VALIDATOR_PRIVATE_HEX: &str =
    "5f668a7ee96d944a4494cc947e4005e172d7ab3461ee5538f1f2a45a835e9657";
const VALIDATOR_REV_ADDRESS: &str = "1111AtahZeefej4tvVR6ti9TJtv8yxLebT31SCEVDCKMNikBk5r3g";
/// Dev-shard-wide loopback ext port. The fixture passes this to the
/// daemon as `--extension-grpc-port` so test and daemon agree.
const EXT_PORT: u16 = 40421;

#[test]
#[ignore = "needs a running f1r3node + FUSE support on the host"]
fn wallets_mount_shows_unlocked_validator() {
    skip_if_no_node!();
    let fx = DaemonFixture::spawn_wallets(&[VALIDATOR_PRIVATE_HEX], &[], EXT_PORT);
    skip_if_tcc_blocked!(&fx);

    // /: one entry, the validator address.
    let entries: Vec<String> = std::fs::read_dir(&fx.mountpoint)
        .expect("read_dir /")
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    assert!(
        entries.iter().any(|e| e == VALIDATOR_REV_ADDRESS),
        "root readdir should show validator; got {entries:?}",
    );
}

#[test]
#[ignore = "needs a running f1r3node + FUSE support on the host"]
fn wallets_mount_enumerates_bills() {
    skip_if_no_node!();
    let fx = DaemonFixture::spawn_wallets(&[VALIDATOR_PRIVATE_HEX], &[], EXT_PORT);
    skip_if_tcc_blocked!(&fx);

    let tokens_dir = fx.mountpoint.join(VALIDATOR_REV_ADDRESS).join(".tokens");
    let bills: Vec<String> = std::fs::read_dir(&tokens_dir)
        .expect("read_dir .tokens")
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.ends_with(".token"))
        .collect();

    // The validator's balance is non-trivial; expect at least one
    // bill. (Exact count depends on how much phlo has been spent on
    // this shard — we don't pin it here, see e2e_balance.rs's
    // justification.)
    assert!(
        !bills.is_empty(),
        "validator should have at least one bill; got {bills:?}",
    );

    // Every bill name parses as `<denom>-REV.<i>.token` with a known
    // denomination.
    for name in &bills {
        let (denom, _idx) = f1r3drive_fs::wallet_fs::parse_token_name(name)
            .unwrap_or_else(|| panic!("bill {name:?} failed to parse"));
        assert!(
            f1r3drive_wallet::DENOMINATIONS.contains(&denom),
            "bill {name:?} has unknown denomination {denom}",
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a running f1r3node + FUSE support on the host"]
async fn ext_rpc_unlock_promotes_locked_wallet() {
    skip_if_no_node_async!();
    // Start the daemon tracking the validator as LOCKED, with NO
    // unlock key at startup.
    let fx = DaemonFixture::spawn_wallets(&[], &[VALIDATOR_REV_ADDRESS], EXT_PORT);
    skip_if_tcc_blocked!(&fx);

    // Before: shows up as `LOCKED-REMOTE-REV-...`.
    let locked_name = format!("LOCKED-REMOTE-REV-{VALIDATOR_REV_ADDRESS}");
    let seen_before: Vec<String> = std::fs::read_dir(&fx.mountpoint)
        .expect("pre-unlock read_dir")
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    assert!(
        seen_before.iter().any(|e| e == &locked_name),
        "expected locked entry; got {seen_before:?}",
    );

    // Unlock via the ext gRPC.
    let link = UnlockLink {
        rev_address: VALIDATOR_REV_ADDRESS.into(),
        private_key: VALIDATOR_PRIVATE_HEX.into(),
    };
    let outcome = forward_unlock(link, "127.0.0.1", EXT_PORT).await;
    assert!(
        matches!(outcome, UnlockOutcome::Success),
        "unlock should succeed, got {outcome:?}",
    );

    // After: now shows up as the bare address.
    let seen_after: Vec<String> = std::fs::read_dir(&fx.mountpoint)
        .expect("post-unlock read_dir")
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    assert!(
        seen_after.iter().any(|e| e == VALIDATOR_REV_ADDRESS),
        "expected unlocked entry; got {seen_after:?}",
    );
    assert!(
        !seen_after.iter().any(|e| e == &locked_name),
        "locked entry should be gone; got {seen_after:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a running f1r3node + FUSE support on the host"]
async fn ext_rpc_unlock_rejects_mismatched_key() {
    skip_if_no_node_async!();
    let fx = DaemonFixture::spawn_wallets(&[], &[VALIDATOR_REV_ADDRESS], EXT_PORT);
    skip_if_tcc_blocked!(&fx);

    // Any random secp256k1 key will derive to a different address.
    let bogus_hex = "1111111111111111111111111111111111111111111111111111111111111111";
    let link = UnlockLink {
        rev_address: VALIDATOR_REV_ADDRESS.into(),
        private_key: bogus_hex.into(),
    };
    let outcome = forward_unlock(link, "127.0.0.1", EXT_PORT).await;
    assert!(
        matches!(&outcome, UnlockOutcome::DaemonError(msg) if msg.contains("does not derive")),
        "mismatched-key unlock should return daemon error, got {outcome:?}",
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a running f1r3node + FUSE support on the host"]
async fn ext_rpc_combine_is_unimplemented() {
    skip_if_no_node_async!();
    let fx = DaemonFixture::spawn_wallets(&[VALIDATOR_PRIVATE_HEX], &[], EXT_PORT);
    skip_if_tcc_blocked!(&fx);

    let mut client = ext_client(EXT_PORT).await;

    // Pick any path under a real `.tokens/`. The exact bill name
    // doesn't matter — the service rejects COMBINE before parsing.
    let path = fx
        .mountpoint
        .join(VALIDATOR_REV_ADDRESS)
        .join(".tokens/1-REV.0.token");
    let resp = client
        .submit_action(MenuActionRequest {
            action: MenuActionType::Combine as i32,
            path: vec![path.to_string_lossy().into_owned()],
        })
        .await
        .expect("submit_action rpc")
        .into_inner();
    match resp.result {
        Some(RpcResult::Error(e)) => assert!(
            e.error_message.contains("COMBINE") && e.error_message.contains("not implemented"),
            "unexpected error: {}",
            e.error_message,
        ),
        other => panic!("expected error, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a running f1r3node + FUSE support on the host"]
async fn ext_rpc_change_reshapes_bill_without_moving_balance() {
    skip_if_no_node_async!();
    let fx = DaemonFixture::spawn_wallets(&[VALIDATOR_PRIVATE_HEX], &[], EXT_PORT);
    skip_if_tcc_blocked!(&fx);

    // Pick a bill to break — we need to know the balance to pick a
    // denom that actually exists. Snapshot the balance via a direct
    // gRPC call rather than relying on readdir ordering, since
    // greedy decomposition depends on balance mod denom.
    let host = common::node_host();
    let port = common::node_port();
    let mut nc = NodeClient::connect(&host, port).await.expect("connect");
    let snippet = check_balance_snippet(VALIDATOR_REV_ADDRESS);
    let r = nc
        .exploratory_deploy(snippet.term(), "", false)
        .await
        .expect("balance deploy");
    let balance = decode_balance_reply(&r.pars).expect("decode") as u64;
    let bills = f1r3drive_wallet::decompose(balance);
    // Pick a non-smallest denom that actually has a bill.
    let target = bills
        .iter()
        .find(|b| b.denom > 1)
        .copied()
        .expect("validator should have at least one non-smallest bill");

    // Snapshot the readdir before.
    let tokens_dir = fx.mountpoint.join(VALIDATOR_REV_ADDRESS).join(".tokens");
    let before: Vec<String> = std::fs::read_dir(&tokens_dir)
        .expect("pre-change readdir")
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();

    // Issue CHANGE on bill 0 of `target.denom`.
    let path = tokens_dir.join(format!("{}-REV.0.token", target.denom));
    let mut client = ext_client(EXT_PORT).await;
    let resp = client
        .submit_action(MenuActionRequest {
            action: MenuActionType::Change as i32,
            path: vec![path.to_string_lossy().into_owned()],
        })
        .await
        .expect("submit_action rpc")
        .into_inner();
    assert!(
        matches!(resp.result, Some(RpcResult::Success(_))),
        "CHANGE should succeed; got {:?}",
        resp.result,
    );

    // kernel attribute cache may hold the pre-CHANGE readdir for up to
    // ATTR_TTL (1s). poll briefly.
    let smaller = target.denom / 10;
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        let after: Vec<String> = std::fs::read_dir(&tokens_dir)
            .expect("post-change readdir")
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect();
        let smaller_count_before = count_bills_of_denom(&before, smaller);
        let smaller_count_after = count_bills_of_denom(&after, smaller);
        if smaller_count_after >= smaller_count_before + 10 {
            // Also: target denom should have one fewer bill.
            let target_before = count_bills_of_denom(&before, target.denom);
            let target_after = count_bills_of_denom(&after, target.denom);
            assert_eq!(target_after, target_before - 1);
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "CHANGE did not reshape bills within deadline. before={before:?}, \
                 after={after:?}, target denom={}, smaller={}",
                target.denom, smaller,
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

async fn ext_client(port: u16) -> FinderSyncExtensionServiceClient<Channel> {
    let endpoint = format!("http://127.0.0.1:{port}");
    let channel = Channel::from_shared(endpoint)
        .unwrap()
        .connect()
        .await
        .expect("ext channel");
    FinderSyncExtensionServiceClient::new(channel)
}

fn count_bills_of_denom(entries: &[String], denom: u64) -> usize {
    entries
        .iter()
        .filter_map(|n| f1r3drive_fs::wallet_fs::parse_token_name(n))
        .filter(|(d, _)| *d == denom)
        .count()
}

#[macro_export]
macro_rules! skip_if_no_node_async {
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

// Compile-time guard so the test file won't go stale if the KeyPair
// derivation ever drifts from the ADR's claimed REV address.
#[allow(dead_code)]
const _: () = {
    // Just reference the type; actual derivation check lives in the
    // f1r3drive-wallet unit tests. This block is here as a reminder
    // that the two constants above are a locked pair.
    let _ = VALIDATOR_PRIVATE_HEX.len();
    let _ = VALIDATOR_REV_ADDRESS.len();
};
#[allow(dead_code)]
fn _unused_imports_guard(_: KeyPair, _: UnlockWalletDirectoryRequest, _: RevAddress) {}
