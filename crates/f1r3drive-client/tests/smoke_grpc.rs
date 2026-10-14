//! Live gRPC smoke test. Requires a running f1r3node (e.g. local docker shard
//! from `f1r3node-rust/docker/shard.yml`). Marked `#[ignore]` so plain
//! `cargo test` doesn't fail without the shard; run with:
//!
//! ```shell
//! cargo test -p f1r3drive-client --test smoke_grpc -- --ignored --nocapture
//! ```

use f1r3drive_client::{DeployToSign, KeyPair, NodeClient};

/// Placeholder 32-byte secp256k1 scalar for the sign/do_deploy
/// roundtrip test. **Not** a key published by any F1R3FLY project —
/// lexically-chosen test fixture. Override with your real dev-shard
/// key via the `F1R3DRIVE_TEST_SK` env var when exercising this test
/// against a live shard; the key must correspond to a bonded validator
/// in that shard's genesis.
const DEV_SHARD_SK_HEX: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const DEV_HOST: &str = "127.0.0.1";
const DEV_PORT: u16 = 40401;
const DEV_SHARD_ID: &str = "root";

#[tokio::test]
#[ignore]
async fn exploratory_deploy_nil_returns_cost() {
    let mut client = NodeClient::connect(DEV_HOST, DEV_PORT)
        .await
        .expect("connect");
    let result = client
        .exploratory_deploy("Nil", "", false)
        .await
        .expect("exploratory_deploy");
    // Nil evaluates to Nil, so pars is a single empty Par; cost is nonzero.
    println!("cost={} pars={}", result.cost, result.pars.len());
}

#[tokio::test]
#[ignore]
async fn do_deploy_then_propose_roundtrip() {
    let sk_hex =
        std::env::var("F1R3DRIVE_TEST_SK").unwrap_or_else(|_| DEV_SHARD_SK_HEX.to_string());
    let key = KeyPair::from_private_hex(&sk_hex).expect("key");
    let mut client = NodeClient::connect(DEV_HOST, DEV_PORT)
        .await
        .expect("connect");

    let unsigned = DeployToSign::new_now("Nil", DEV_SHARD_ID);
    let signed = unsigned.sign(&key).expect("sign");
    let ack = client.do_deploy(signed).await.expect("do_deploy");
    println!("deploy ack: {}", ack.message);

    let propose = client.propose(false).await.expect("propose");
    println!("propose ack: {}", propose.message);
}
