//! End-to-end paid-transfer flow against a running f1r3node shard.
//!
//! Three tests, each `#[ignore]`-gated so `cargo test` without the
//! shard still passes cleanly:
//!
//! 1. `mint_returns_a_listing_uri` — Alice deploys the factory via
//!    `paid_transfer_mint`; the deploy result decodes as a `GUri`
//!    (not bytes — slice-14 initially assumed bytes; this test
//!    caught the discrepancy and slice 15 corrected it).
//! 2. `mint_reply_has_the_tagged_shape` — defensive guard against
//!    the Rholang factory drifting away from the `[true, uri]`
//!    reply contract.
//! 3. `burn_deploy_admits_under_either_signer` — mint under Alice,
//!    then burn under both Alice and Bob. Both must at least admit
//!    (deploy enters the pool). Reply-shape validation of the
//!    owner-check needs `getDataAtName` wiring; slice 16 adds that.
//!
//! All of these need a shard reachable at
//! `F1R3DRIVE_NODE_HOST:F1R3DRIVE_NODE_PORT` (defaults to
//! `127.0.0.1:40401`). Bring one up from `f1r3node-rust`:
//!
//! ```sh
//! cd ../f1r3node-rust/docker && docker compose -f standalone.yml up -d
//! # ... wait for /api/ready on :40403 ...
//! cargo test -p f1r3drive --test e2e_paid_transfer -- --ignored
//! ```
//!
//! The purchase flow (SELF-wrap of a real file, Alice→Bob REV
//! transfer, Bob decrypts via K_listing) is slice 16; it needs the
//! `ExtensionFs` daemon wiring on top of this harness.

mod common;

use f1r3drive_client::{DeployToSign, KeyPair, NodeClient};
use f1r3drive_rho::{
    decode_mint_reply, decode_reply, paid_transfer_burn, paid_transfer_mint, FsReply,
};

/// Alice's dev signing key — standalone bootstrap/validator key from
/// `f1r3node-rust/docker/.env`. Her vault is pre-funded in genesis
/// (`standalone-wallets.txt`) so mint deploys can pay phlo.
const ALICE_PRIVATE_KEY_HEX: &str =
    "5f668a7ee96d944a4494cc947e4005e172d7ab3461ee5538f1f2a45a835e9657";

/// Alice's REV address, derived from the same key by the standalone
/// genesis script. Pinned so the test is deterministic — if genesis
/// derivation drifts, update both constants in lock-step with
/// `standalone-wallets.txt`.
const ALICE_REV_ADDRESS: &str = "1111AtahZeefej4tvVR6ti9TJtv8yxLebT31SCEVDCKMNikBk5r3g";

/// Bob's dev signing key — reuse a non-genesis validator key so
/// `burn` sees a *different* deployer id than the mint. Note Bob's
/// vault isn't funded, so purchase-flow tests have to pre-fund via
/// a REV transfer from Alice; this slice only exercises mint + burn
/// which don't need Bob to pay.
const BOB_PRIVATE_KEY_HEX: &str =
    "357cdc4201a5650830e0bc5a03299a30038d9934ba4c7ab73ec164ad82471ff9";

/// Must match the shard's `--shard-id`; default dev shards use
/// `"root"`.
const SHARD_ID: &str = "root";

/// Submit a signed deploy under `signer`, propose a block, return the
/// reply decoded from the deploy's return channel via a follow-up
/// `exploratory_deploy` against the same term shape. Admission +
/// propose cover the signed-write path; the exploratory call lets us
/// pull the mint URI (which the mutating path doesn't surface
/// through `post_block_data`).
///
/// The caveat: the mint deploy allocates fresh unforgeable names, so
/// a second exploratory of the same term produces a *different* URI.
/// We instead rely on the fact that `insertArbitrary` registers
/// durable state; the exploratory lookup against the first URI should
/// still resolve the factory. The two tests below cover both halves.
async fn submit_signed(
    client: &mut NodeClient,
    signer: &KeyPair,
    term: &str,
) -> Result<(), String> {
    let mut to_sign = DeployToSign::new_now(term.to_string(), SHARD_ID.to_string());
    match client.status().await {
        Ok(s) => to_sign.valid_after_block_number = s.last_finalized_block_number.max(0),
        Err(e) if e.is_unimplemented() => {}
        Err(e) => return Err(format!("status: {e}")),
    }
    let signed = to_sign.sign(signer).map_err(|e| format!("sign: {e}"))?;
    client
        .do_deploy(signed)
        .await
        .map_err(|e| format!("deploy: {e}"))?;
    // Standalone shards auto-propose; a follow-up explicit propose
    // can race and surface "No new deploys to propose." That's
    // success-equivalent for admission, so we filter it out.
    match client.propose(false).await {
        Ok(_) => Ok(()),
        Err(e) => {
            let msg = format!("{e}");
            if msg.contains("No new deploys") {
                Ok(())
            } else {
                Err(format!("propose: {e}"))
            }
        }
    }
}

#[tokio::test]
#[ignore = "needs a running f1r3node on the configured endpoint"]
async fn mint_returns_a_listing_uri() {
    skip_if_no_node_async!();

    let host = common::node_host();
    let port = common::node_port();
    let mut client = NodeClient::connect(&host, port)
        .await
        .expect("connect to node");

    let alice = KeyPair::from_private_hex(ALICE_PRIVATE_KEY_HEX).expect("parse alice key");

    // Encrypted blob + K_listing shape is opaque to the factory —
    // use fixed test bytes so the Rholang literal is small.
    let encrypted_blob = b"ciphertext-stand-in";
    let k_listing = [0x11u8; 32];

    let mint = paid_transfer_mint(ALICE_REV_ADDRESS, 1_000, encrypted_blob, &k_listing);

    // The mutating path doesn't surface the deploy's return value,
    // so we probe via an exploratory deploy of the same source. The
    // exploratory re-executes the mint — producing a *fresh* URI,
    // but that's enough to validate that the Rholang parses, the
    // vault lookup succeeds, and `insertArbitrary` returns a byte
    // array. If any of those break we'll see FSERR / decode errors.
    let exploratory = client
        .exploratory_deploy(mint.term(), "", false)
        .await
        .expect("exploratory mint");
    let reply = decode_reply(&exploratory.pars).expect("decode reply shape");
    let uri = decode_mint_reply(reply).expect("mint reply must carry a URI");
    assert!(!uri.is_empty(), "listing URI should be non-empty bytes");

    // Now do the real signed deploy so a persistent factory lives
    // on-chain — slice 16 uses this to validate purchase.
    submit_signed(&mut client, &alice, mint.term())
        .await
        .expect("signed mint deploy");
}

#[tokio::test]
#[ignore = "needs a running f1r3node on the configured endpoint"]
async fn burn_deploy_admits_under_either_signer() {
    // Slice 15 proves the burn deploy is well-formed enough to
    // admit under both the owner's and a non-owner's signing
    // context. The actual owner-check behavior (did the factory
    // reply [false, FSERR_PERM, ...] for Bob? [true] for Alice?)
    // needs `getDataAtName` on the deploy's return channel, which
    // this client doesn't yet speak. Slice 16 wires that and
    // promotes this to a real end-to-end assertion.
    skip_if_no_node_async!();

    let host = common::node_host();
    let port = common::node_port();
    let mut client = NodeClient::connect(&host, port)
        .await
        .expect("connect to node");

    let alice = KeyPair::from_private_hex(ALICE_PRIVATE_KEY_HEX).expect("parse alice key");
    let bob = KeyPair::from_private_hex(BOB_PRIVATE_KEY_HEX).expect("parse bob key");

    // Alice mints a durable factory under her signing identity.
    let mint = paid_transfer_mint(ALICE_REV_ADDRESS, 1, b"burn-target", &[0x22u8; 32]);
    submit_signed(&mut client, &alice, mint.term())
        .await
        .expect("alice signed mint");

    // Grab a URI via exploratory (produces a fresh factory, not
    // necessarily Alice's — but any valid factory URI exercises
    // the deploy wiring, which is what slice 15 asserts).
    let exploratory = client
        .exploratory_deploy(mint.term(), "", false)
        .await
        .expect("exploratory mint for URI");
    let reply = decode_reply(&exploratory.pars).expect("decode mint reply");
    let uri = decode_mint_reply(reply).expect("URI from mint");

    // Both signers should at least admit a burn deploy — the
    // Rholang parses, the factory lookup resolves, and the deploy
    // enters the pool. Reply-shape validation is slice 16.
    let burn = paid_transfer_burn(&uri);
    submit_signed(&mut client, &alice, burn.term())
        .await
        .expect("owner burn admits");
    submit_signed(&mut client, &bob, burn.term())
        .await
        .expect("non-owner burn admits (reply shape not asserted here)");
}

#[tokio::test]
#[ignore = "needs a running f1r3node on the configured endpoint"]
async fn mint_reply_has_the_tagged_shape() {
    // Guards against a Rholang-side change breaking the reply
    // contract. Any `FsReply::Ok { payload }` with a non-empty byte
    // array as the first element is accepted; the deeper shape
    // (uri bytes = whatever `insertArbitrary` returned) is already
    // asserted in `mint_returns_a_listing_uri`.
    skip_if_no_node_async!();

    let host = common::node_host();
    let port = common::node_port();
    let mut client = NodeClient::connect(&host, port)
        .await
        .expect("connect to node");

    let mint = paid_transfer_mint(ALICE_REV_ADDRESS, 1, b"x", &[0u8; 32]);
    let exploratory = client
        .exploratory_deploy(mint.term(), "", false)
        .await
        .expect("exploratory mint");
    let reply = decode_reply(&exploratory.pars).expect("decode");
    match reply {
        FsReply::Ok { payload } => {
            assert!(!payload.is_empty(), "mint ok reply must carry a URI");
        }
        FsReply::Err(e) => panic!(
            "mint should succeed on a fresh factory: {}: {}",
            e.code, e.message
        ),
    }
}

/// Async flavour of the standard skip macro — see e2e_balance.rs.
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
