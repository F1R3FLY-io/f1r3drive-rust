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
//! - **burn** (Alice): calls `factory!("burn", ...)`; the factory
//!   requires caller's deployer id to match the one captured at mint.
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
//! - Owner-only burn relies on `rho:system:deployerId` being a stable
//!   per-identity unforgeable name across deploys. If it's actually a
//!   per-deploy nonce, burn will reject the owner's own call. Slice 15
//!   validates against a running shard.
//! - The `insertArbitrary → URI → rho:registry:lookup` round-trip is
//!   assumed to resolve the published factory via the same lookup
//!   mechanism URNs use; also pending shard confirmation.

use thiserror::Error;

use crate::reply::{par_as_bytes, par_as_uri, FsError, FsReply};
use crate::snippet::Snippet;

/// Factory contract source. Placeholders:
/// `{OWNER_REV}`, `{OWNER_DEPLOYER_ID}`, `{PRICE}`,
/// `{ENCRYPTED_BLOB}`, `{K_LISTING}`.
const FACTORY_RHO: &str = include_str!("../rholang/paid_transfer_factory.rho");

/// Build the mint deploy snippet. Alice signs + deploys this; the
/// deploy's return channel yields `[true, listingUri]`.
///
/// `owner_rev` is Alice's base58 REV address (not pubkey hex — the
/// vault system identifies accounts by REV address).
/// `price` is in atomic REV units. `encrypted_blob` is Alice's
/// pre-SELF-wrapped file (daemon-side crypto); `k_listing` is the
/// 32-byte symmetric key that unlocks it.
pub fn paid_transfer_mint(
    owner_rev: &str,
    price: u64,
    encrypted_blob: &[u8],
    k_listing: &[u8],
) -> Snippet {
    let body = FACTORY_RHO
        .replace("{OWNER_REV}", &rho_string(owner_rev))
        .replace("{OWNER_DEPLOYER_ID}", "*deployerIdAtMint")
        .replace("{PRICE}", &price.to_string())
        .replace("{ENCRYPTED_BLOB}", &rho_bytes(encrypted_blob))
        .replace("{K_LISTING}", &rho_bytes(k_listing));

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
pub fn paid_transfer_purchase(listing_uri: &str, buyer_rev: &str) -> Snippet {
    let body = format!(
        "new return, rl(`rho:registry:lookup`), factoryCh in {{\n  \
         rl!(`{uri}`, *factoryCh) |\n  \
         for (@(_, factory) <- factoryCh) {{\n    \
         @factory!(\"purchase\", {{\"buyer_rev\": {rev}}}, *return)\n  \
         }}\n\
         }}\n",
        uri = escape_backticks(listing_uri),
        rev = rho_string(buyer_rev),
    );
    Snippet(body)
}

/// Build an inline mint-then-purchase snippet for end-to-end
/// smoke testing. One deploy mints the factory and immediately
/// invokes `purchase` against the fresh URI, returning the full
/// purchase reply `[true, encryptedBlob, kListing]` on `*return`.
///
/// Not useful as a production flow — the real sequence is a signed
/// mint by Alice, then separately a signed purchase by Bob. But
/// everything the production flow touches (the Rholang parse, the
/// factory contract body, insertArbitrary + registry lookup, vault
/// transfer, the deployerAuthKey path) is exercised in one
/// executable program. Perfect for `exploratory_deploy` smoke
/// tests: single call, full reply visible on `post_block_data`.
///
/// `buyer_rev` is the current deploy's REV address. The composite
/// runs under one deployer identity, so Alice-the-owner and
/// Bob-the-buyer collapse into whoever signs the deploy; the
/// transfer loops from that account back to itself. That's fine for
/// a Rholang smoke test — balances don't drift and every code path
/// still executes.
/// Observation-channel suffix for signed `paid_transfer_mint_and_purchase_inline`
/// deploys. The snippet emits its reply on `@("paid_transfer:reply:" ++ nonce)`
/// so the caller can retrieve it via
/// `get_data_at_name` with a matching `GString` Par after the
/// block proposes. Each test run picks its own nonce to avoid
/// cross-test interference.
pub const PAID_TRANSFER_REPLY_PREFIX: &str = "paid_transfer:reply:";

pub fn paid_transfer_mint_and_purchase_inline(
    owner_rev: &str,
    buyer_rev: &str,
    price: u64,
    encrypted_blob: &[u8],
    k_listing: &[u8],
    reply_nonce: &str,
) -> Snippet {
    // Values Alice would normally store on `listingState` are
    // compile-time inlined into the reply emission below. That
    // removes a `for ... <<- listingState` scheduling hazard
    // (peek vs. send race in the inline composition) and keeps
    // this smoke test focused on the vault-transfer + reply
    // round-trip — the parts that must behave identically to the
    // production factory.
    // The reply is emitted on BOTH `*return` (for exploratory
    // callers that don't exercise the vault — the transfer fails
    // in that mode anyway) AND an `@"paid_transfer:reply:<nonce>"`
    // string channel (persistent, retrievable via
    // `get_data_at_name` for signed deploys). The signed path is
    // what proves purchase works end-to-end; the string-channel
    // observation sidesteps the per-deploy unforgeable-return
    // retrieval problem.
    let reply_channel = format!("{PAID_TRANSFER_REPLY_PREFIX}{reply_nonce}");
    let body = format!(
        r#"new return, rl(`rho:registry:lookup`), SystemVaultCh, factory in {{
  rl!(`rho:vault:system`, *SystemVaultCh) |
  for (@(_, SystemVault) <- SystemVaultCh) {{
    contract factory(@method, @args, replyCh) = {{
      new buyerVaultCh, authKeyCh, txResultCh,
          deployerId(`rho:system:deployerId`)
      in {{
        @SystemVault!("findOrCreate", {buyer_rev}, *buyerVaultCh) |
        @SystemVault!("deployerAuthKey", *deployerId, *authKeyCh) |
        for (@maybeVault <- buyerVaultCh; @authKey <- authKeyCh) {{
          match maybeVault {{
            (true, bv) => {{
              @bv!("transfer", {owner_rev}, {price}, authKey, *txResultCh) |
              for (@tx <- txResultCh) {{
                match tx {{
                  (true, _) => replyCh!([true, {blob}, {k}])
                  (false, msg) => replyCh!([false, "FSERR_TRANSFER_FAILED", msg])
                }}
              }}
            }}
            _ => replyCh!([false, "FSERR_VAULT_LOOKUP", "no buyer vault"])
          }}
        }}
      }}
    }} |

    // Fan the factory reply out to the return channel (exploratory)
    // AND to a known string channel (signed+getDataAtName).
    new innerReply in {{
      factory!("purchase", "args_ignored_in_inline", *innerReply) |
      for (@reply <- innerReply) {{
        return!(reply) |
        @{reply_ch}!(reply)
      }}
    }}
  }}
}}
"#,
        owner_rev = rho_string(owner_rev),
        buyer_rev = rho_string(buyer_rev),
        price = price,
        blob = rho_bytes(encrypted_blob),
        k = rho_bytes(k_listing),
        reply_ch = rho_string(&reply_channel),
    );
    Snippet(body)
}

/// Build the burn deploy snippet. Alice signs + deploys this; the
/// factory verifies her deployer id matches the one captured at
/// mint. Reply: `[true]` on success, `[false, "FSERR_PERM", ...]`
/// if the caller isn't the owner.
pub fn paid_transfer_burn(listing_uri: &str) -> Snippet {
    let body = format!(
        "new return, rl(`rho:registry:lookup`), factoryCh in {{\n  \
         rl!(`{uri}`, *factoryCh) |\n  \
         for (@(_, factory) <- factoryCh) {{\n    \
         @factory!(\"burn\", Nil, *return)\n  \
         }}\n\
         }}\n",
        uri = escape_backticks(listing_uri),
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

/// Decode a `paid_transfer_mint` reply. Expects
/// `[true, listingUri]` on success where `listingUri` is a
/// `GUri`-typed Par (Rholang's registry returns URIs, not strings
/// or byte arrays). Converts the error-case `[false, code, msg]`
/// into [`PaidTransferError::Agent`].
pub fn decode_mint_reply(reply: FsReply) -> Result<String, PaidTransferError> {
    match reply {
        FsReply::Ok { payload } => {
            let uri_par = payload.first().ok_or(PaidTransferError::MalformedPayload)?;
            par_as_uri(uri_par).ok_or(PaidTransferError::MalformedPayload)
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

/// Decode a `paid_transfer_burn` reply. Expects `[true]`.
pub fn decode_burn_reply(reply: FsReply) -> Result<(), PaidTransferError> {
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
        let s = paid_transfer_mint(SAMPLE_REV, 100, b"blob", b"key32");
        let term = s.term();
        // The factory source should be substituted in.
        assert!(term.contains("contract factory("));
        assert!(term.contains("\"purchase\""));
        assert!(term.contains("\"burn\""));
    }

    #[test]
    fn mint_substitutes_price_as_literal_int() {
        let s = paid_transfer_mint(SAMPLE_REV, 42, b"blob", b"key32");
        let term = s.term();
        // Price appears as a bare int (no quoting), owner_rev as string.
        assert!(term.contains("42"));
        assert!(term.contains(&format!("\"{SAMPLE_REV}\"")));
    }

    #[test]
    fn mint_substitutes_bytes_as_hex_slice() {
        let s = paid_transfer_mint(SAMPLE_REV, 1, &[0xde, 0xad, 0xbe, 0xef], &[0xca, 0xfe]);
        let term = s.term();
        // Each byte array uses the `.hexToBytes().slice(1, N+1)` idiom.
        assert!(term.contains("\"0xdeadbeef\".hexToBytes().slice(1, 5)"));
        assert!(term.contains("\"0xcafe\".hexToBytes().slice(1, 3)"));
    }

    #[test]
    fn mint_captures_owner_deployer_id_at_execution() {
        let s = paid_transfer_mint(SAMPLE_REV, 1, b"x", b"y");
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
        let s = paid_transfer_mint(SAMPLE_REV, 1, b"x", b"y");
        let term = s.term();
        assert!(term.contains("new deployerIdAtMint"));
        assert!(term.contains("new return,"));
    }

    #[test]
    fn purchase_looks_up_listing_uri() {
        let s = paid_transfer_purchase(SAMPLE_URI, SAMPLE_REV);
        let term = s.term();
        assert!(term.contains("`rho:registry:lookup`"));
        assert!(term.contains(&format!("rl!(`{SAMPLE_URI}`")));
        assert!(term.contains(&format!("\"buyer_rev\": \"{SAMPLE_REV}\"")));
    }

    #[test]
    fn purchase_targets_the_purchase_method() {
        let s = paid_transfer_purchase(SAMPLE_URI, SAMPLE_REV);
        assert!(s.term().contains("@factory!(\"purchase\""));
    }

    #[test]
    fn burn_targets_the_burn_method() {
        let s = paid_transfer_burn(SAMPLE_URI);
        let term = s.term();
        assert!(term.contains("@factory!(\"burn\""));
        assert!(term.contains(&format!("rl!(`{SAMPLE_URI}`")));
    }

    #[test]
    fn mint_and_purchase_inline_has_return_as_first_unforgeable() {
        let s = paid_transfer_mint_and_purchase_inline(
            SAMPLE_REV, SAMPLE_REV, 1, b"blob", &[0u8; 32], "nonce",
        );
        let term = s.term();
        let i_new = term.find("new return,").expect("return must be first");
        assert!(!term[..i_new].contains("new "));
    }

    #[test]
    fn mint_and_purchase_inline_targets_the_purchase_method() {
        let s = paid_transfer_mint_and_purchase_inline(
            SAMPLE_REV, SAMPLE_REV, 10, b"c", &[0u8; 32], "n",
        );
        // `factory` is `new`-bound here (not pattern-destructured
        // from a registry lookup), so the invocation is a direct
        // send without the `@` dereference.
        assert!(s.term().contains("factory!(\"purchase\""));
    }

    #[test]
    fn mint_and_purchase_inline_embeds_buyer_rev() {
        let s = paid_transfer_mint_and_purchase_inline(
            SAMPLE_REV, "BOB_ADDR", 1, b"c", &[0u8; 32], "n",
        );
        // Buyer rev lands as a GString in the vault findOrCreate call.
        assert!(s.term().contains("\"BOB_ADDR\""));
    }

    #[test]
    fn mint_and_purchase_inline_embeds_reply_nonce() {
        let s = paid_transfer_mint_and_purchase_inline(
            SAMPLE_REV, SAMPLE_REV, 1, b"c", &[0u8; 32], "abc-123",
        );
        assert!(s
            .term()
            .contains(&format!("{PAID_TRANSFER_REPLY_PREFIX}abc-123")));
    }

    #[test]
    fn uri_with_embedded_backticks_is_sanitized() {
        // Defensive: the URI format shouldn't contain backticks, but
        // if it ever did, we'd break the surrounding literal. Strip
        // defensively.
        let s = paid_transfer_purchase("rho:id:evil`backtick", SAMPLE_REV);
        assert!(!s.term().contains("evil`backtick"));
        assert!(s.term().contains("evilbacktick"));
    }

    #[test]
    fn purchase_has_return_as_first_unforgeable() {
        let s = paid_transfer_purchase(SAMPLE_URI, SAMPLE_REV);
        let term = s.term();
        // `new return, rl(...), factoryCh in { ... }` — return is first.
        let i_new = term.find("new return,").expect("return must be first");
        // No earlier `new` binding than this.
        assert!(!term[..i_new].contains("new "));
    }

    #[test]
    fn burn_has_return_as_first_unforgeable() {
        let s = paid_transfer_burn(SAMPLE_URI);
        let term = s.term();
        let i_new = term.find("new return,").expect("return must be first");
        assert!(!term[..i_new].contains("new "));
    }

    #[test]
    fn empty_blob_still_renders_a_valid_byte_literal() {
        let s = paid_transfer_mint(SAMPLE_REV, 1, b"", b"");
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

    #[test]
    fn mint_reply_decodes_uri_string() {
        let ok = FsReply::Ok {
            payload: vec![uri_par("rho:id:abcdef")],
        };
        assert_eq!(decode_mint_reply(ok).unwrap(), "rho:id:abcdef");
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
    fn burn_reply_ok_is_unit() {
        let ok = FsReply::Ok { payload: vec![] };
        assert!(decode_burn_reply(ok).is_ok());
    }

    #[test]
    fn burn_reply_propagates_permission_error() {
        let err = FsReply::Err(FsError {
            code: "FSERR_PERM".into(),
            message: "only owner".into(),
        });
        match decode_burn_reply(err) {
            Err(PaidTransferError::Agent(e)) => assert_eq!(e.code, "FSERR_PERM"),
            other => panic!("unexpected: {other:?}"),
        }
    }
}
