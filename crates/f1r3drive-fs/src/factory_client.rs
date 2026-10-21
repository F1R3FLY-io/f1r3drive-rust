//! On-chain Paid-transfer factory client.
//!
//! Composes `f1r3drive-client` + `f1r3drive-rho::paid_transfer_*` so
//! `ExtensionFs` can issue mint / rmdir / purchase deploys from
//! inside FUSE callbacks. Mirrors the sign + propose +
//! get_data_at_name pattern proven out by the slice-16 e2e tests:
//!
//! - **mint**: sign + propose a `paid_transfer_mint`, pull the
//!   factory URI off `@"paid_transfer:mint-reply:<nonce>"`.
//! - **rmdir**: sign + propose a `paid_transfer_rmdir`, pull the
//!   factory reply off `@"paid_transfer:rmdir-reply:<nonce>"`,
//!   decode as `[true]` or `[false, FSERR_PERM, ...]`.
//! - **purchase**: sign + propose a `paid_transfer_purchase`, pull
//!   `[true, encryptedBlob, kListing]` off the deploy's reply
//!   channel.
//!
//! All methods are synchronous — they block the FUSE callback on
//! `tokio::runtime::Handle::block_on`. The caller is expected to
//! hold the client in a `tokio::sync::Mutex` + clone the Arc per
//! request if concurrency becomes a goal.
//!
//! The purchase path uses a per-call string channel too (not the
//! factory's internal `*return`), identical to how slice-15 wired
//! the composite smoke test — this is the only observation
//! mechanism that works for mutating deploys without re-executing
//! under exploratory.

use std::sync::Arc;

use rand::{rngs::OsRng, TryRngCore};
use thiserror::Error;
use tokio::runtime::Handle;
use tracing::warn;

use f1r3drive_client::{ClientError, DeployToSign, KeyPair, NodeClient};
use f1r3drive_rho::{
    decode_mint_reply, decode_purchase_reply, decode_reply, decode_rmdir_reply, paid_transfer_mint,
    paid_transfer_rmdir, PaidTransferError, PurchasePayload, PAID_TRANSFER_MINT_REPLY_PREFIX,
    PAID_TRANSFER_REPLY_PREFIX, PAID_TRANSFER_RMDIR_REPLY_PREFIX,
};

/// On-chain factory operations issued from inside FUSE callbacks.
pub struct FactoryClient {
    runtime: Handle,
    client: Arc<tokio::sync::Mutex<NodeClient>>,
    signer: KeyPair,
    shard_id: String,
    manual_propose: bool,
}

/// What a mint deploy returned on-chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintedListing {
    /// The `rho:id:<base58>` URI that resolves to the factory.
    pub listing_uri: String,
    /// Base58 REV address of the factory-owned escrow vault that
    /// buyers must transfer `price` REV into before invoking the
    /// factory's `release` method. The factory holds the
    /// unforgeable seed that keys this vault, so sweep + buyer-side
    /// transfers both succeed in their respective scopes without
    /// cross-identity authKey forwarding.
    pub escrow_address: String,
}

#[derive(Debug, Error)]
pub enum FactoryError {
    #[error("node client: {0:?}")]
    Client(ClientError),
    #[error("sign: {0}")]
    Sign(String),
    #[error("propose returned no block hash")]
    NoBlockHash,
    #[error("reply channel empty after propose — deploy may not have executed")]
    EmptyReply,
    #[error("agent: {0}")]
    Agent(PaidTransferError),
    #[error("decode: {0:?}")]
    Decode(f1r3drive_rho::DecodeError),
}

pub type FactoryResult<T> = std::result::Result<T, FactoryError>;

impl FactoryClient {
    pub fn new(
        runtime: Handle,
        client: NodeClient,
        signer: KeyPair,
        shard_id: String,
        manual_propose: bool,
    ) -> Self {
        Self {
            runtime,
            client: Arc::new(tokio::sync::Mutex::new(client)),
            signer,
            shard_id,
            manual_propose,
        }
    }

    /// Mint a factory on-chain for `(price, encrypted_blob, k_listing)`.
    /// `plaintext_filename` is encoded into the Rholang contract as the
    /// publicly-visible filename for buyers.
    pub fn mint_listing(
        &self,
        owner_rev: &str,
        price: u64,
        encrypted_blob: &[u8],
        k_listing: &[u8],
    ) -> FactoryResult<MintedListing> {
        let nonce = fresh_nonce();
        let snippet = paid_transfer_mint(owner_rev, price, encrypted_blob, k_listing, &nonce);
        let channel = format!("{PAID_TRANSFER_MINT_REPLY_PREFIX}{nonce}");
        let reply = self.sign_propose_fetch(snippet.term(), &channel)?;
        let payload = decode_mint_reply(reply).map_err(FactoryError::Agent)?;
        Ok(MintedListing {
            listing_uri: payload.listing_uri,
            escrow_address: payload.escrow_address,
        })
    }

    /// Burn a listing. The factory's owner-check compares the caller's
    /// deployer id (passed as the deploy's `args`) against the one
    /// captured at mint; non-owner callers receive `FSERR_PERM`.
    pub fn rmdir_listing(&self, listing_uri: &str) -> FactoryResult<()> {
        let nonce = fresh_nonce();
        let snippet = paid_transfer_rmdir(listing_uri, &nonce);
        let channel = format!("{PAID_TRANSFER_RMDIR_REPLY_PREFIX}{nonce}");
        let reply = self.sign_propose_fetch(snippet.term(), &channel)?;
        decode_rmdir_reply(reply).map_err(FactoryError::Agent)
    }

    /// Invoke the full buyer-side purchase flow for a listing.
    ///
    /// This is NOT a single factory method invocation; it's one
    /// signed deploy from the buyer that:
    ///
    /// 1. Looks up SystemVault + the factory URI.
    /// 2. Resolves the buyer's authKey in the deploy's OWN scope
    ///    (see `feedback_paid_transfer_authkey_ocap` for why
    ///    forwarding fails).
    /// 3. Transfers `price` REV from the buyer's vault to
    ///    `escrow_address` (the factory-owned escrow vault).
    /// 4. On transfer success, invokes `factory.release(buyer_rev)`
    ///    which verifies the escrow balance has advanced by at
    ///    least `price * (releasedCount + 1)` and emits
    ///    `[true, encryptedBlob, kListing]`.
    ///
    /// `buyer_rev` must correspond to the signer's REV address;
    /// `escrow_address` + `price` come from the listing's `.info`
    /// record (populated at mint time by `decode_mint_reply`).
    ///
    /// The reply observes on a per-call string channel so signed
    /// deploys can retrieve it via `get_data_at_name` after the
    /// block proposes.
    pub fn purchase_listing(
        &self,
        listing_uri: &str,
        buyer_rev: &str,
        escrow_address: &str,
        price: u64,
    ) -> FactoryResult<PurchasePayload> {
        let nonce = fresh_nonce();
        let channel = format!("{PAID_TRANSFER_REPLY_PREFIX}{nonce}");
        // Hoist the shared snippet's shape here, rewired so the
        // factory's reply fans out to BOTH the deploy's `*return`
        // (exploratory callers) AND a per-nonce string channel
        // (signed callers retrieve via `get_data_at_name`). The
        // alternative — composing a wrapper around the shared
        // snippet's `*return` — isn't readable enough given the
        // snippet is 25 lines of nested forwarding.
        let term = format!(
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
             return!(reply) |\n                  \
             @{reply_ch}!(reply)\n                \
             }}\n              \
             }}\n              \
             (false, msg) => {{\n                \
             return!([false, \"FSERR_TRANSFER_FAILED\", msg]) |\n                \
             @{reply_ch}!([false, \"FSERR_TRANSFER_FAILED\", msg])\n              \
             }}\n            \
             }}\n          \
             }}\n        \
             }}\n        \
             _ => {{\n          \
             return!([false, \"FSERR_VAULT_LOOKUP\", \"no buyer vault\"]) |\n          \
             @{reply_ch}!([false, \"FSERR_VAULT_LOOKUP\", \"no buyer vault\"])\n        \
             }}\n      \
             }}\n    \
             }}\n  \
             }}\n\
             }}\n",
            uri = listing_uri,
            rev = rho_string(buyer_rev),
            escrow = rho_string(escrow_address),
            price = price,
            reply_ch = rho_string(&channel),
        );
        let reply = self.sign_propose_fetch(&term, &channel)?;
        decode_purchase_reply(reply).map_err(FactoryError::Agent)
    }

    /// Shared signed-deploy + reply-fetch flow. Signs + submits
    /// `term`, pulls the longest hex run out of the ProposeAck
    /// message, queries `get_data_at_name` on `GString(reply_channel)`
    /// at that block, decodes the trailing Par as a reply.
    fn sign_propose_fetch(
        &self,
        term: &str,
        reply_channel: &str,
    ) -> FactoryResult<f1r3drive_rho::FsReply> {
        let term = term.to_string();
        let shard_id = self.shard_id.clone();
        let manual_propose = self.manual_propose;
        let signer = self.signer.clone();
        let client = self.client.clone();
        let channel = reply_channel.to_string();

        self.runtime.block_on(async move {
            let mut guard = client.lock().await;
            let mut to_sign = DeployToSign::new_now(term, shard_id);
            match guard.status().await {
                Ok(s) => to_sign.valid_after_block_number = s.last_finalized_block_number.max(0),
                Err(e) if e.is_unimplemented() => {}
                Err(e) => return Err(FactoryError::Client(e)),
            }
            let signed = to_sign
                .sign(&signer)
                .map_err(|e| FactoryError::Sign(e.to_string()))?;
            guard
                .do_deploy(signed)
                .await
                .map_err(FactoryError::Client)?;

            let block_hash = if manual_propose {
                return Err(FactoryError::NoBlockHash);
            } else {
                match guard.propose(false).await {
                    Ok(ack) => extract_block_hash(&ack.message),
                    Err(e) => {
                        let msg = format!("{e}");
                        if msg.contains("No new deploys") {
                            None
                        } else {
                            return Err(FactoryError::Client(e));
                        }
                    }
                }
            }
            .ok_or(FactoryError::NoBlockHash)?;

            let pars = guard
                .get_data_at_name(
                    NodeClient::string_channel_name(&channel),
                    &block_hash,
                    false,
                )
                .await
                .map_err(FactoryError::Client)?;
            if pars.is_empty() {
                warn!(
                    channel,
                    "reply channel empty — deploy may have failed server-side"
                );
                return Err(FactoryError::EmptyReply);
            }
            // Take the most recent Par as the reply (channels are
            // cumulative; multiple deploys to the same channel land
            // here in order).
            decode_reply(&pars[pars.len() - 1..]).map_err(FactoryError::Decode)
        })
    }
}

/// Nanoseconds since epoch as a hex nonce. Unique per call within a
/// process; serial_test guarantees no overlap across concurrent tests.
fn fresh_nonce() -> String {
    let mut buf = [0u8; 8];
    OsRng
        .try_fill_bytes(&mut buf)
        .expect("OS CSPRNG required for nonce");
    hex::encode(buf)
}

fn extract_block_hash(msg: &str) -> Option<String> {
    msg.split_whitespace()
        .filter(|w| w.len() >= 32 && w.chars().all(|c| c.is_ascii_hexdigit()))
        .max_by_key(|w| w.len())
        .map(str::to_string)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_nonce_is_16_hex() {
        let n = fresh_nonce();
        assert_eq!(n.len(), 16);
        assert!(n.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fresh_nonce_differs_per_call() {
        // 64-bit entropy — collision probability negligible.
        assert_ne!(fresh_nonce(), fresh_nonce());
    }

    #[test]
    fn extract_block_hash_grabs_longest_hex_run() {
        let msg = "Success! Block abc123def456789012345678901234567890abcd created and added.";
        assert_eq!(
            extract_block_hash(msg).as_deref(),
            Some("abc123def456789012345678901234567890abcd")
        );
    }

    #[test]
    fn extract_block_hash_none_when_no_hash() {
        assert_eq!(extract_block_hash("something unrelated"), None);
    }
}
