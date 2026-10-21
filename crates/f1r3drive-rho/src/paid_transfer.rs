//! Rholang snippets for the ADR-0002 Paid-transfer factory.
//!
//! Three verbs, deployed by different parties:
//!
//! - **mint** (Alice): embeds the factory contract source + Alice's
//!   listing state + stores + registers at a listing URI. Reply:
//!   `[true, listingUri]`. The URI is Alice's listing's public address.
//! - **purchase** (Bob): looks up the listing URI, calls
//!   `factory!("purchase", {buyer_rev}, ...)`. The factory validates
//!   the REV transfer and replies with the encrypted blob + K_listing.
//! - **rmdir** (Alice): calls `factory!("rmdir", ...)`; the factory
//!   requires caller's deployer id to match the one captured at mint.
//!   Method name mirrors the FUSE call that triggers this deploy —
//!   `rmdir /<listing-uuid>/` on the mount surface.
//!
//! The canonical Rholang source for the factory lives in
//! `../rholang/paid_transfer_factory.rho`; this module embeds it via
//! `include_str!` and substitutes placeholders at build time.
//!
//! All three snippets land their reply on `*return` (first unforgeable
//! name in the top-level `new`). Reply shape mirrors the `Fs` agent's:
//! `[true, ...]` on success, `[false, code, msg]` on failure.
//!
//! Known caveats (shard-verification pending):
//!
//! - Owner-only rmdir relies on `rho:system:deployerId` being a stable
//!   per-identity unforgeable name across deploys. If it's actually a
//!   per-deploy nonce, rmdir will reject the owner's own call. Slice 15
//!   validates against a running shard.
//! - The `insertArbitrary → URI → rho:registry:lookup` round-trip is
//!   assumed to resolve the published factory via the same lookup
//!   mechanism URNs use; also pending shard confirmation.

use thiserror::Error;

use crate::reply::{par_as_bytes, par_as_string, par_as_uri, FsError, FsReply};
use crate::snippet::Snippet;

/// Factory contract source. Placeholders:
/// `{OWNER_REV}`, `{OWNER_DEPLOYER_ID}`, `{PRICE}`,
/// `{ENCRYPTED_BLOB}`, `{K_LISTING}`, `{MINT_REPLY_CHANNEL}`.
const FACTORY_RHO: &str = include_str!("../rholang/paid_transfer_factory.rho");

/// Prefix for the per-deploy observation channel the mint snippet
/// emits its URI on. Signed deploys retrieve via `get_data_at_name`
/// against `GString("<prefix><nonce>")`. Each deploy picks its own
/// nonce so concurrent tests don't collide.
pub const PAID_TRANSFER_MINT_REPLY_PREFIX: &str = "paid_transfer:mint-reply:";

/// Prefix for the per-deploy observation channel the `rmdir` snippet
/// emits the factory reply on. Same shape as the mint-reply prefix.
pub const PAID_TRANSFER_RMDIR_REPLY_PREFIX: &str = "paid_transfer:rmdir-reply:";

/// Build the mint deploy snippet. Alice signs + deploys this; the
/// deploy's return channel yields `[true, listingUri]`, and the
/// same reply fans out to `@"paid_transfer:mint-reply:<reply_nonce>"`
/// so signed callers can retrieve the URI via `get_data_at_name`.
///
/// `owner_rev` is Alice's base58 REV address (not pubkey hex — the
/// vault system identifies accounts by REV address).
/// `price` is in atomic REV units. `encrypted_blob` is Alice's
/// pre-SELF-wrapped file (daemon-side crypto); `k_listing` is the
/// 32-byte symmetric key that unlocks it. `reply_nonce` must be
/// unique per deploy for signed callers to find their own URI.
pub fn paid_transfer_mint(
    owner_rev: &str,
    price: u64,
    encrypted_blob: &[u8],
    k_listing: &[u8],
    reply_nonce: &str,
) -> Snippet {
    let reply_channel = format!("{PAID_TRANSFER_MINT_REPLY_PREFIX}{reply_nonce}");
    let body = FACTORY_RHO
        .replace("{OWNER_REV}", &rho_string(owner_rev))
        .replace("{OWNER_DEPLOYER_ID}", "*deployerIdAtMint")
        .replace("{PRICE}", &price.to_string())
        .replace("{ENCRYPTED_BLOB}", &rho_bytes(encrypted_blob))
        .replace("{K_LISTING}", &rho_bytes(k_listing))
        .replace("{MINT_REPLY_CHANNEL}", &rho_string(&reply_channel));

    // The factory source expects `deployerIdAtMint` to be the owner's
    // deployer id — captured at the mint deploy's execution context.
    // Wrap the factory in an outer `new deployerIdAtMint(...)` so the
    // substitution refers to a bound name, not free text.
    let wrapped = format!(
        "new deployerIdAtMint(`rho:system:deployerId`) in {{\n{factory}\n}}\n",
        factory = body,
    );
    Snippet(wrapped)
}

/// Build the purchase deploy snippet. Bob signs + deploys this; the
/// deploy's return channel yields `[true, encryptedBlob, kListing]`
/// on success or `[false, code, msg]` on vault / payment failure.
///
/// `listing_uri` is the `rho:id:...` string returned by
/// [`decode_mint_reply`]. `buyer_rev` is Bob's own REV address — the
/// factory derives his auth key from the current deploy's
/// `deployerId`, so Bob must sign this deploy with the key matching
/// that address.
pub fn paid_transfer_purchase(
    listing_uri: &str,
    buyer_rev: &str,
    escrow_address: &str,
    price: u64,
) -> Snippet {
    // Composite: Bob's deploy transfers `price` REV from his vault
    // to the factory-owned escrow address IN HIS OWN SCOPE
    // (deployerAuthKey resolves correctly here — see
    // `feedback_paid_transfer_authkey_ocap` for why forwarding
    // through the factory doesn't work), then calls
    // `factory!("release", buyer_rev, ...)` which verifies the
    // escrow balance has advanced by `price * (releasedCount + 1)`
    // and emits `[true, encryptedBlob, kListing]`.
    //
    // The whole thing is one deploy so the transfer + release are
    // atomic from the caller's perspective: either both land in the
    // same block (and the release observes the balance bump) or
    // neither does (admission or propose failure).
    let body = format!(
        "new return, rl(`rho:registry:lookup`),\n    \
         SystemVaultCh, factoryCh,\n    \
         deployerId(`rho:system:deployerId`),\n    \
         authKeyCh, buyerVaultCh, txResultCh, factoryReply\n\
         in {{\n  \
         rl!(`rho:vault:system`, *SystemVaultCh) |\n  \
         rl!(`{uri}`, *factoryCh) |\n  \
         for (@(_, SystemVault) <- SystemVaultCh; @(_, factory) <- factoryCh) {{\n    \
         @SystemVault!(\"deployerAuthKey\", *deployerId, *authKeyCh) |\n    \
         @SystemVault!(\"findOrCreate\", {rev}, *buyerVaultCh) |\n    \
         for (@authKey <- authKeyCh; @maybeVault <- buyerVaultCh) {{\n      \
         match maybeVault {{\n        \
         (true, buyerVault) => {{\n          \
         @buyerVault!(\"transfer\", {escrow}, {price}, authKey, *txResultCh) |\n          \
         for (@tx <- txResultCh) {{\n            \
         match tx {{\n              \
         (true, _) => {{\n                \
         @factory!(\"release\", {rev}, *factoryReply) |\n                \
         for (@reply <- factoryReply) {{\n                  \
         return!(reply)\n                \
         }}\n              \
         }}\n              \
         (false, msg) => return!([false, \"FSERR_TRANSFER_FAILED\", msg])\n            \
         }}\n          \
         }}\n        \
         }}\n        \
         _ => return!([false, \"FSERR_VAULT_LOOKUP\", \"no buyer vault\"])\n      \
         }}\n    \
         }}\n  \
         }}\n\
         }}\n",
        uri = escape_backticks(listing_uri),
        rev = rho_string(buyer_rev),
        escrow = rho_string(escrow_address),
        price = price,
    );
    Snippet(body)
}

/// Observation-channel prefix for `FactoryClient::purchase_listing`'s
/// per-call reply channel. Signed-deploy callers can retrieve the
/// factory's `release` reply via `get_data_at_name` with a
/// matching `GString` Par after the block proposes. Each call
/// picks its own nonce so concurrent purchases don't collide.
pub const PAID_TRANSFER_REPLY_PREFIX: &str = "paid_transfer:reply:";

/// Build the rmdir deploy snippet — the on-chain half of
/// `rmdir /<listing-uuid>/` on the mount surface. Alice signs +
/// deploys this; the factory verifies her deployer id matches the
/// one captured at mint. Reply: `[true]` on success,
/// `[false, "FSERR_PERM", ...]` if the caller isn't the owner.
///
/// Fans the reply out to both `*return` (exploratory) and
/// `@"paid_transfer:rmdir-reply:<reply_nonce>"` (signed, retrievable
/// via `get_data_at_name`). The nonce must be unique per deploy so
/// concurrent tests can't collide on observation channels.
pub fn paid_transfer_rmdir(listing_uri: &str, reply_nonce: &str) -> Snippet {
    let reply_channel = format!("{PAID_TRANSFER_RMDIR_REPLY_PREFIX}{reply_nonce}");
    // Capture the caller's deployer identity in this deploy's own
    // context and pass it to the factory as the `args` parameter.
    // Reading `rho:system:deployerId` inside the stored factory
    // body would resolve to the FACTORY-PUBLISHER's identity, not
    // the current invoker's — see the factory source's "rmdir" arm
    // for the rationale.
    let body = format!(
        "new return, rl(`rho:registry:lookup`),\n    \
         factoryCh, factoryReply,\n    \
         callerDeployerId(`rho:system:deployerId`)\n\
         in {{\n  \
         rl!(`{uri}`, *factoryCh) |\n  \
         for (@(_, factory) <- factoryCh) {{\n    \
         @factory!(\"rmdir\", *callerDeployerId, *factoryReply) |\n    \
         for (@reply <- factoryReply) {{\n      \
         return!(reply) |\n      \
         @{reply_ch}!(reply)\n    \
         }}\n  \
         }}\n\
         }}\n",
        uri = escape_backticks(listing_uri),
        reply_ch = rho_string(&reply_channel),
    );
    Snippet(body)
}

/// Interpolate a URI inside a backtick literal. URIs returned by
/// `insertArbitrary` are `rho:id:<base58>` — no backticks, printable
/// ASCII. We defensively strip any backtick anyway so a drifted URI
/// shape can't break the surrounding Rholang parse.
fn escape_backticks(s: &str) -> String {
    s.chars().filter(|c| *c != '`').collect()
}

/// What `decode_mint_reply` returns: both the registry URI the
/// factory published itself at AND the escrow vault address the
/// buyer must transfer their payment into. Both live in the daemon's
/// `Listing` record so a prospective buyer with only the listing
/// uuid can resolve everything needed to purchase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintReplyPayload {
    pub listing_uri: String,
    pub escrow_address: String,
}

/// Decode a `paid_transfer_mint` reply. Expects
/// `[true, listingUri, escrowAddress]` on success where
/// `listingUri` is a `GUri`-typed Par (the Rholang registry returns
/// URIs, not strings) and `escrowAddress` is a `GString`-typed Par
/// (base58 REV address). Converts the error-case
/// `[false, code, msg]` into [`PaidTransferError::Agent`].
pub fn decode_mint_reply(reply: FsReply) -> Result<MintReplyPayload, PaidTransferError> {
    match reply {
        FsReply::Ok { payload } => {
            if payload.len() < 2 {
                return Err(PaidTransferError::MalformedPayload);
            }
            let listing_uri = par_as_uri(&payload[0]).ok_or(PaidTransferError::MalformedPayload)?;
            let escrow_address =
                par_as_string(&payload[1]).ok_or(PaidTransferError::MalformedPayload)?;
            Ok(MintReplyPayload {
                listing_uri,
                escrow_address,
            })
        }
        FsReply::Err(e) => Err(PaidTransferError::Agent(e)),
    }
}

/// Decode a `paid_transfer_purchase` reply. Expects
/// `[true, encryptedBlob_bytes, kListing_bytes]`. The caller's
/// daemon decrypts the blob with `k_listing` locally and re-wraps
/// as a RECV for the buyer's own prefix.
pub fn decode_purchase_reply(reply: FsReply) -> Result<PurchasePayload, PaidTransferError> {
    match reply {
        FsReply::Ok { payload } => {
            if payload.len() < 2 {
                return Err(PaidTransferError::MalformedPayload);
            }
            let encrypted_blob = par_as_bytes(&payload[0])
                .ok_or(PaidTransferError::MalformedPayload)?
                .to_vec();
            let k_listing = par_as_bytes(&payload[1])
                .ok_or(PaidTransferError::MalformedPayload)?
                .to_vec();
            Ok(PurchasePayload {
                encrypted_blob,
                k_listing,
            })
        }
        FsReply::Err(e) => Err(PaidTransferError::Agent(e)),
    }
}

/// Decode a `paid_transfer_rmdir` reply. Expects `[true]`.
pub fn decode_rmdir_reply(reply: FsReply) -> Result<(), PaidTransferError> {
    match reply {
        FsReply::Ok { .. } => Ok(()),
        FsReply::Err(e) => Err(PaidTransferError::Agent(e)),
    }
}

/// Successful payload of a paid-transfer purchase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurchasePayload {
    pub encrypted_blob: Vec<u8>,
    pub k_listing: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum PaidTransferError {
    #[error("factory reply didn't match the expected payload shape")]
    MalformedPayload,
    #[error("factory returned {0}")]
    Agent(#[source] FsError),
}

/// Quote a plain string as a Rholang `GString` literal. Mirrors the
/// private helper in `snippet.rs`; duplicated here because that one
/// isn't `pub(crate)` yet and we don't want to churn the Fs-agent
/// module just to expose it.
fn rho_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Emit a Rholang `ByteArray` literal from a `&[u8]`.
fn rho_bytes(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "\"\".hexToBytes()".to_string();
    }
    let n = bytes.len();
    format!(
        "\"0x{}\".hexToBytes().slice(1, {end})",
        hex::encode(bytes),
        end = n + 1,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_REV: &str = "1111K9yPC9j8VKKrGpUYsvNvjJfJrqgSE4QxWw7XGxJyKS89mv1DJWQ";
    const SAMPLE_URI: &str = "rho:id:sample5x7xq1k4e5tbxcbdxdxg7swrq1i4bzifiynbf5a1zqnpdbf6s";

    #[test]
    fn mint_embeds_factory_contract() {
        let s = paid_transfer_mint(SAMPLE_REV, 100, b"blob", b"key32", "n");
        let term = s.term();
        // The factory source should be substituted in.
        assert!(term.contains("contract factory("));
        // Methods on the factory. "purchase" was renamed to
        // "release" when the authKey-forwarding wall forced the
        // escrow-based redesign (see
        // feedback_paid_transfer_authkey_ocap).
        assert!(term.contains("\"release\""));
        assert!(term.contains("\"rmdir\""));
    }

    #[test]
    fn mint_substitutes_price_as_literal_int() {
        let s = paid_transfer_mint(SAMPLE_REV, 42, b"blob", b"key32", "n");
        let term = s.term();
        // Price appears as a bare int (no quoting), owner_rev as string.
        assert!(term.contains("42"));
        assert!(term.contains(&format!("\"{SAMPLE_REV}\"")));
    }

    #[test]
    fn mint_substitutes_bytes_as_hex_slice() {
        let s = paid_transfer_mint(SAMPLE_REV, 1, &[0xde, 0xad, 0xbe, 0xef], &[0xca, 0xfe], "n");
        let term = s.term();
        // Each byte array uses the `.hexToBytes().slice(1, N+1)` idiom.
        assert!(term.contains("\"0xdeadbeef\".hexToBytes().slice(1, 5)"));
        assert!(term.contains("\"0xcafe\".hexToBytes().slice(1, 3)"));
    }

    #[test]
    fn mint_captures_owner_deployer_id_at_execution() {
        let s = paid_transfer_mint(SAMPLE_REV, 1, b"x", b"y", "n");
        let term = s.term();
        // Outer wrapper binds a fresh `deployerIdAtMint` channel.
        assert!(term.contains("new deployerIdAtMint(`rho:system:deployerId`)"));
    }

    #[test]
    fn mint_has_return_as_first_unforgeable() {
        // The on-chain runtime pulls the deploy's return from the
        // FIRST unforgeable name allocated at the top-level `new`.
        // The outer wrapper's first name is `deployerIdAtMint`, so
        // the factory's own `new return, ...` becomes the second-level
        // frame. Verify both wrappers are present.
        let s = paid_transfer_mint(SAMPLE_REV, 1, b"x", b"y", "n");
        let term = s.term();
        assert!(term.contains("new deployerIdAtMint"));
        assert!(term.contains("new return,"));
    }

    const SAMPLE_ESCROW: &str = "11112EscrowSampleAddr____________________________xxxx";

    #[test]
    fn purchase_looks_up_listing_uri_and_system_vault() {
        let s = paid_transfer_purchase(SAMPLE_URI, SAMPLE_REV, SAMPLE_ESCROW, 50);
        let term = s.term();
        assert!(term.contains("`rho:registry:lookup`"));
        assert!(term.contains("rl!(`rho:vault:system`"));
        assert!(term.contains(&format!("rl!(`{SAMPLE_URI}`")));
    }

    #[test]
    fn purchase_resolves_authkey_in_buyer_scope() {
        let s = paid_transfer_purchase(SAMPLE_URI, SAMPLE_REV, SAMPLE_ESCROW, 50);
        let term = s.term();
        // Buyer's deploy news `deployerId` and asks SystemVault for
        // the matching authKey — the critical "in-scope" bit that
        // the ocap-forwarding attempts couldn't do from the factory.
        assert!(term.contains("deployerId(`rho:system:deployerId`)"));
        assert!(term.contains("\"deployerAuthKey\""));
    }

    #[test]
    fn purchase_transfers_price_to_escrow_before_release() {
        let s = paid_transfer_purchase(SAMPLE_URI, SAMPLE_REV, SAMPLE_ESCROW, 99);
        let term = s.term();
        // The buyer's vault is debited `price` into the escrow
        // address FIRST; only on txResult=(true, _) is the factory's
        // release method invoked.
        assert!(term.contains(&format!(
            "@buyerVault!(\"transfer\", \"{SAMPLE_ESCROW}\", 99, authKey, *txResultCh)"
        )));
        assert!(term.contains("@factory!(\"release\""));
    }

    #[test]
    fn purchase_bails_on_transfer_failure() {
        let s = paid_transfer_purchase(SAMPLE_URI, SAMPLE_REV, SAMPLE_ESCROW, 1);
        let term = s.term();
        // A failed buyerVault.transfer must NOT invoke release.
        // The snippet routes a (false, msg) tx into
        // `[false, "FSERR_TRANSFER_FAILED", msg]`.
        assert!(term.contains("FSERR_TRANSFER_FAILED"));
    }

    #[test]
    fn rmdir_targets_the_rmdir_method() {
        let s = paid_transfer_rmdir(SAMPLE_URI, "n");
        let term = s.term();
        assert!(term.contains("@factory!(\"rmdir\""));
        assert!(term.contains(&format!("rl!(`{SAMPLE_URI}`")));
    }

    #[test]
    fn uri_with_embedded_backticks_is_sanitized() {
        // Defensive: the URI format shouldn't contain backticks, but
        // if it ever did, we'd break the surrounding literal. Strip
        // defensively.
        let s = paid_transfer_purchase("rho:id:evil`backtick", SAMPLE_REV, SAMPLE_ESCROW, 1);
        assert!(!s.term().contains("evil`backtick"));
        assert!(s.term().contains("evilbacktick"));
    }

    #[test]
    fn purchase_has_return_as_first_unforgeable() {
        let s = paid_transfer_purchase(SAMPLE_URI, SAMPLE_REV, SAMPLE_ESCROW, 1);
        let term = s.term();
        // `new return, rl(...), ... in { ... }` — return is first.
        let i_new = term.find("new return,").expect("return must be first");
        // No earlier `new` binding than this.
        assert!(!term[..i_new].contains("new "));
    }

    #[test]
    fn rmdir_has_return_as_first_unforgeable() {
        let s = paid_transfer_rmdir(SAMPLE_URI, "n");
        let term = s.term();
        let i_new = term.find("new return,").expect("return must be first");
        assert!(!term[..i_new].contains("new "));
    }

    #[test]
    fn empty_blob_still_renders_a_valid_byte_literal() {
        let s = paid_transfer_mint(SAMPLE_REV, 1, b"", b"", "n");
        let term = s.term();
        assert!(term.contains("\"\".hexToBytes()"));
    }

    // Reply-decoder tests build synthetic `FsReply`s directly so we
    // don't need a running shard.

    use crate::reply::FsError;
    use f1r3drive_proto::rhoapi::expr::ExprInstance;
    use f1r3drive_proto::rhoapi::{Expr, Par};

    fn bytes_par(b: &[u8]) -> Par {
        Par {
            exprs: vec![Expr {
                expr_instance: Some(ExprInstance::GByteArray(b.to_vec())),
            }],
            ..Par::default()
        }
    }

    fn uri_par(uri: &str) -> Par {
        Par {
            exprs: vec![Expr {
                expr_instance: Some(ExprInstance::GUri(uri.to_string())),
            }],
            ..Par::default()
        }
    }

    fn string_par(s: &str) -> Par {
        Par {
            exprs: vec![Expr {
                expr_instance: Some(ExprInstance::GString(s.to_string())),
            }],
            ..Par::default()
        }
    }

    #[test]
    fn mint_reply_decodes_uri_and_escrow_address() {
        let ok = FsReply::Ok {
            payload: vec![
                uri_par("rho:id:abcdef"),
                string_par("11112EscrowSampleAddr____________________________xxxx"),
            ],
        };
        let payload = decode_mint_reply(ok).unwrap();
        assert_eq!(payload.listing_uri, "rho:id:abcdef");
        assert_eq!(
            payload.escrow_address,
            "11112EscrowSampleAddr____________________________xxxx"
        );
    }

    #[test]
    fn mint_reply_rejects_missing_escrow_address() {
        // Old mint reply shape had only `[true, uri]`. Make sure
        // we actually require the escrow slot now.
        let ok = FsReply::Ok {
            payload: vec![uri_par("rho:id:abcdef")],
        };
        assert!(matches!(
            decode_mint_reply(ok),
            Err(PaidTransferError::MalformedPayload)
        ));
    }

    #[test]
    fn mint_reply_rejects_bytes_in_uri_slot() {
        // Guards against drift: GByteArray in the URI slot used to be
        // what we accepted; the shard actually returns GUri. If
        // someone changes the Rholang factory to return bytes, this
        // test flags it.
        let ok = FsReply::Ok {
            payload: vec![bytes_par(&[1, 2, 3])],
        };
        assert!(matches!(
            decode_mint_reply(ok),
            Err(PaidTransferError::MalformedPayload)
        ));
    }

    #[test]
    fn mint_reply_propagates_agent_errors() {
        let err = FsReply::Err(FsError {
            code: "FSERR_UNKNOWN_METHOD".into(),
            message: "oops".into(),
        });
        assert!(matches!(
            decode_mint_reply(err),
            Err(PaidTransferError::Agent(_))
        ));
    }

    #[test]
    fn mint_reply_rejects_missing_payload() {
        let ok = FsReply::Ok { payload: vec![] };
        assert!(matches!(
            decode_mint_reply(ok),
            Err(PaidTransferError::MalformedPayload)
        ));
    }

    #[test]
    fn purchase_reply_decodes_blob_and_key() {
        let ok = FsReply::Ok {
            payload: vec![bytes_par(b"ciphertext"), bytes_par(b"keybytes")],
        };
        let payload = decode_purchase_reply(ok).unwrap();
        assert_eq!(payload.encrypted_blob, b"ciphertext");
        assert_eq!(payload.k_listing, b"keybytes");
    }

    #[test]
    fn purchase_reply_rejects_short_payload() {
        let ok = FsReply::Ok {
            payload: vec![bytes_par(b"only-one")],
        };
        assert!(matches!(
            decode_purchase_reply(ok),
            Err(PaidTransferError::MalformedPayload)
        ));
    }

    #[test]
    fn rmdir_reply_ok_is_unit() {
        let ok = FsReply::Ok { payload: vec![] };
        assert!(decode_rmdir_reply(ok).is_ok());
    }

    #[test]
    fn rmdir_reply_propagates_permission_error() {
        let err = FsReply::Err(FsError {
            code: "FSERR_PERM".into(),
            message: "only owner".into(),
        });
        match decode_rmdir_reply(err) {
            Err(PaidTransferError::Agent(e)) => assert_eq!(e.code, "FSERR_PERM"),
            other => panic!("unexpected: {other:?}"),
        }
    }
}
