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
//! 3. `rmdir_deploy_admits_under_either_signer` — mint under Alice,
//!    then rmdir under both Alice and Bob. Both must at least admit
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
use f1r3drive_crypto::{envelope, generate_key};
use f1r3drive_rho::{
    decode_mint_reply, decode_purchase_reply, decode_reply, paid_transfer_mint,
    paid_transfer_mint_and_purchase_inline, paid_transfer_rmdir, FsReply,
    PAID_TRANSFER_REPLY_PREFIX,
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
/// `rmdir` sees a *different* deployer id than the mint. Note Bob's
/// vault isn't funded, so purchase-flow tests have to pre-fund via
/// a REV transfer from Alice; this slice only exercises mint + rmdir
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
) -> Result<Option<String>, String> {
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
    // success-equivalent for admission, so we filter it out. On
    // success the ProposeAck message carries the block hash we need
    // for get_data_at_name queries.
    match client.propose(false).await {
        Ok(ack) => Ok(extract_block_hash(&ack.message)),
        Err(e) => {
            let msg = format!("{e}");
            if msg.contains("No new deploys") {
                Ok(None)
            } else {
                Err(format!("propose: {e}"))
            }
        }
    }
}

/// Pull the block hash out of a propose ack. The server returns a
/// human-readable string like `"Success! Block <hash> created and
/// added."`; we grab the longest hex run as the hash.
fn extract_block_hash(msg: &str) -> Option<String> {
    msg.split_whitespace()
        .filter(|w| w.len() >= 32 && w.chars().all(|c| c.is_ascii_hexdigit()))
        .max_by_key(|w| w.len())
        .map(str::to_string)
}

#[tokio::test]
#[serial_test::serial]
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
#[serial_test::serial]
#[ignore = "needs a running f1r3node on the configured endpoint"]
async fn complete_paid_transfer_flow_decrypts_the_sold_file() {
    // The slice-16 capstone: Alice SELF-wraps a file, deploys the
    // composite mint+purchase program, pulls the purchase reply off
    // the deploy's return channel, and decrypts the released blob
    // with the released K_listing. The plaintext must match the
    // original. If any link in that chain breaks — Rholang parse,
    // factory contract, vault transfer, insertArbitrary, reply
    // decode, or SELF-envelope round-trip — this test fails.
    //
    // The inline program collapses Alice-the-owner and
    // Bob-the-buyer into a single deployer identity (the signer of
    // this deploy, Alice). The vault transfer loops from Alice's
    // vault back to itself; balances don't drift. The full code
    // path still executes, which is what we're asserting.
    skip_if_no_node_async!();

    let host = common::node_host();
    let port = common::node_port();
    let mut client = NodeClient::connect(&host, port)
        .await
        .expect("connect to node");

    // Plaintext Alice wants to sell. Wrap it as a SELF envelope
    // under a fresh K so the test exercises the real crypto path.
    let plaintext = b"this file is behind a paywall";
    let plaintext_filename = "manuscript.txt";
    let k_listing = generate_key();
    let (envelope, _fp) = envelope::wrap_self(&k_listing, plaintext_filename, plaintext)
        .expect("wrap_self under K_listing");

    // Compose mint-and-purchase into one deploy. The vault
    // transfer needs a real signer context (exploratory lacks one),
    // so this goes through sign + do_deploy + propose. The factory
    // reply lands on a per-run string channel we can retrieve via
    // `get_data_at_name` after the block is in.
    let nonce = format!(
        "{:016x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let snippet = paid_transfer_mint_and_purchase_inline(
        ALICE_REV_ADDRESS,
        ALICE_REV_ADDRESS,
        1_000,
        &envelope.bytes,
        k_listing.as_bytes(),
        &nonce,
    );

    let alice = KeyPair::from_private_hex(ALICE_PRIVATE_KEY_HEX).expect("parse alice key");
    let block_hash = submit_signed(&mut client, &alice, snippet.term())
        .await
        .expect("signed mint+purchase deploy")
        .expect("propose must return a block hash");

    // Query the string channel the snippet emits on.
    let channel_name = format!("{PAID_TRANSFER_REPLY_PREFIX}{nonce}");
    let pars = client
        .get_data_at_name(
            NodeClient::string_channel_name(&channel_name),
            &block_hash,
            false,
        )
        .await
        .expect("get_data_at_name on reply channel");
    assert!(
        !pars.is_empty(),
        "reply channel {channel_name} should carry exactly one factory reply"
    );
    // Take the most recent (last emitted) reply.
    let reply = decode_reply(&pars[pars.len() - 1..]).expect("decode purchase reply from deployId");
    let payload = decode_purchase_reply(reply).expect(
        "purchase must succeed — check the shard logs for FSERR_TRANSFER_FAILED / \
         FSERR_VAULT_LOOKUP",
    );

    // What came back must be exactly what we handed in: the factory
    // is content-opaque, it just stores + releases.
    assert_eq!(
        payload.encrypted_blob, envelope.bytes,
        "released blob should match the SELF envelope Alice minted",
    );
    assert_eq!(
        payload.k_listing,
        k_listing.as_bytes(),
        "released K must match the one Alice minted",
    );

    // The real smoke test: can Bob (= whoever holds K_listing)
    // actually decrypt?
    let decrypted_k = f1r3drive_crypto::SymKey::from_bytes(&payload.k_listing)
        .expect("K_listing must be 32 bytes");
    let unwrapped = envelope::unwrap_self(&decrypted_k, &payload.encrypted_blob)
        .expect("unwrap_self with the released K");
    assert_eq!(unwrapped.plaintext, plaintext);
    assert_eq!(unwrapped.filename, plaintext_filename);
}

#[tokio::test]
#[serial_test::serial]
#[ignore = "needs a running f1r3node on the configured endpoint"]
async fn rmdir_deploy_admits_under_either_signer() {
    // Slice 15 proves the rmdir deploy is well-formed enough to
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
    let mint = paid_transfer_mint(ALICE_REV_ADDRESS, 1, b"rmdir-target", &[0x22u8; 32]);
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

    // Both signers should at least admit an rmdir deploy — the
    // Rholang parses, the factory lookup resolves, and the deploy
    // enters the pool. Reply-shape validation is slice 16.
    let rmdir = paid_transfer_rmdir(&uri);
    submit_signed(&mut client, &alice, rmdir.term())
        .await
        .expect("owner rmdir admits");
    submit_signed(&mut client, &bob, rmdir.term())
        .await
        .expect("non-owner rmdir admits (reply shape not asserted here)");
}

#[tokio::test]
#[serial_test::serial]
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
