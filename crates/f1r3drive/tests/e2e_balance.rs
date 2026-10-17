//! End-to-end balance read against a running f1r3node shard.
//!
//! Doesn't mount a filesystem — just exercises
//! `check_balance_snippet` + `exploratory_deploy` + `decode_balance_reply`
//! and wires them into `BalanceCache`. The `#[ignore]` gate matches
//! the other e2e tests: run with `cargo test -- --ignored`, assuming
//! a shard is up at `F1R3DRIVE_NODE_HOST:F1R3DRIVE_NODE_PORT`
//! (defaults to `127.0.0.1:40401`) with the standalone-dev genesis
//! wallet set.
//!
//! The genesis amount `50_000_000_000_000_000` and the validator REV
//! address are pinned from
//! `f1r3node-rust/docker/genesis/standalone-wallets.txt`. If genesis
//! layout changes, update both constants in lock-step with that file.

mod common;

use std::time::Duration;

use f1r3drive_client::NodeClient;
use f1r3drive_rho::{check_balance_snippet, decode_balance_reply};
use f1r3drive_wallet::{BalanceCache, RevAddress};

const VALIDATOR_REV_ADDRESS: &str = "1111AtahZeefej4tvVR6ti9TJtv8yxLebT31SCEVDCKMNikBk5r3g";
/// Starting balance from `f1r3node-rust/docker/genesis/standalone-wallets.txt`.
const GENESIS_BALANCE: i64 = 50_000_000_000_000_000;
/// Floor the e2e test accepts. The validator's genesis amount gets
/// nibbled by phlo payments on every mutating deploy ever run against
/// this shard, so we don't check for equality — we check that the
/// derivation / decode / cache round-trip surfaces a plausible
/// post-genesis value. "Half the genesis amount" leaves plenty of
/// room for a dev shard that's seen heavy use without masking a real
/// pipeline failure.
const MIN_PLAUSIBLE_BALANCE: i64 = GENESIS_BALANCE / 2;

async fn fetch_balance_via_node(client: &mut NodeClient, addr_b58: String) -> Result<i64, String> {
    let snippet = check_balance_snippet(&addr_b58);
    let result = client
        .exploratory_deploy(snippet.term(), "", false)
        .await
        .map_err(|e| format!("gRPC: {e}"))?;
    decode_balance_reply(&result.pars).map_err(|e| format!("decode: {e}"))
}

#[tokio::test]
#[ignore = "needs a running f1r3node on the configured endpoint"]
async fn validator_balance_matches_genesis() {
    skip_if_no_node_async!();

    let host = common::node_host();
    let port = common::node_port();
    let mut client = NodeClient::connect(&host, port)
        .await
        .expect("connect to node");

    let addr = RevAddress::parse(VALIDATOR_REV_ADDRESS).expect("parse validator rev-address");
    let balance = fetch_balance_via_node(&mut client, addr.to_base58())
        .await
        .expect(
            "fetch validator balance — if this fails with 'Insufficient funds'-style vault errors \
             the standalone-dev wallet set has drifted",
        );
    assert!(
        (MIN_PLAUSIBLE_BALANCE..=GENESIS_BALANCE).contains(&balance),
        "validator balance {balance} outside the plausible range \
         [{MIN_PLAUSIBLE_BALANCE}, {GENESIS_BALANCE}]; either the \
         genesis set drifted, or someone drained more than half of \
         the funded wallet to phlo fees",
    );
}

#[tokio::test]
#[ignore = "needs a running f1r3node on the configured endpoint"]
async fn balance_cache_hits_second_call() {
    skip_if_no_node_async!();

    let host = common::node_host();
    let port = common::node_port();
    let client = std::sync::Arc::new(tokio::sync::Mutex::new(
        NodeClient::connect(&host, port)
            .await
            .expect("connect to node"),
    ));

    let addr = RevAddress::parse(VALIDATOR_REV_ADDRESS).unwrap();
    let cache = BalanceCache::new();

    let c1 = client.clone();
    let first = cache
        .get_or_fetch(&addr, |want| {
            let c1 = c1.clone();
            let b58 = want.to_base58();
            async move {
                let mut g = c1.lock().await;
                fetch_balance_via_node(&mut g, b58).await
            }
        })
        .await
        .expect("first fetch");

    // Second call should NOT hit the node — assert the closure never
    // runs by returning a sentinel error if it does.
    let second = cache
        .get_or_fetch(&addr, |_| async { Err::<i64, _>("must-not-be-called") })
        .await
        .expect("second call must serve from cache");
    assert_eq!(first, second);
}

#[tokio::test]
#[ignore = "needs a running f1r3node on the configured endpoint"]
async fn balance_cache_refreshes_after_ttl() {
    skip_if_no_node_async!();

    let host = common::node_host();
    let port = common::node_port();
    let client = std::sync::Arc::new(tokio::sync::Mutex::new(
        NodeClient::connect(&host, port)
            .await
            .expect("connect to node"),
    ));

    let addr = RevAddress::parse(VALIDATOR_REV_ADDRESS).unwrap();
    let cache = BalanceCache::with_ttl(Duration::from_millis(100));
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    for _ in 0..2 {
        let c = client.clone();
        let counter = calls.clone();
        cache
            .get_or_fetch(&addr, |want| {
                let c = c.clone();
                let counter = counter.clone();
                let b58 = want.to_base58();
                async move {
                    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let mut g = c.lock().await;
                    fetch_balance_via_node(&mut g, b58).await
                }
            })
            .await
            .expect("fetch");
        tokio::time::sleep(Duration::from_millis(150)).await;
    }

    assert_eq!(
        calls.load(std::sync::atomic::Ordering::Relaxed),
        2,
        "cache should have refetched after TTL expired",
    );
}

#[tokio::test]
#[ignore = "needs a running f1r3node on the configured endpoint"]
async fn unfunded_address_returns_zero_or_vault_error() {
    // Any random valid-shape ETH address derives to a REV address
    // the chain's never seen. The vault's `findOrCreate` for an
    // unseen address should either succeed with balance 0 or
    // surface a free-form "no vault" string — both are acceptable
    // from the daemon's point of view (we'd show `0` in the token
    // dir). Pin the two acceptable outcomes to the exact set.
    skip_if_no_node_async!();

    let host = common::node_host();
    let port = common::node_port();
    let mut client = NodeClient::connect(&host, port)
        .await
        .expect("connect to node");

    // A deterministic unfunded address so the test is reproducible.
    let unseen = RevAddress::from_eth_address("deaddeaddeaddeaddeaddeaddeaddeaddeaddead").unwrap();
    match fetch_balance_via_node(&mut client, unseen.to_base58()).await {
        Ok(balance) => assert_eq!(
            balance, 0,
            "unseen vault should start at 0 if it returns a balance",
        ),
        Err(e) => {
            // We ONLY accept the vault-side error path; a gRPC or
            // decode failure here is a real bug.
            assert!(
                e.starts_with("decode: vault returned error:"),
                "expected vault-side error, got: {e}",
            );
        }
    }
}

/// Async flavour of the `skip_if_no_node!` macro — the test fns here
/// are `async`, so an early `return` has to come from inside the
/// async body.
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
