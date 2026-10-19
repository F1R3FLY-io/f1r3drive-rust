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
    paid_transfer_purchase, paid_transfer_rmdir, PaidTransferError, PurchasePayload,
    PAID_TRANSFER_MINT_REPLY_PREFIX, PAID_TRANSFER_REPLY_PREFIX, PAID_TRANSFER_RMDIR_REPLY_PREFIX,
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
        let uri = decode_mint_reply(reply).map_err(FactoryError::Agent)?;
        Ok(MintedListing { listing_uri: uri })
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

    /// Invoke the factory's `purchase` method. The deploy pays the
    /// factory-mandated price from the signer's vault to the listing
    /// owner's vault; on success the factory releases the encrypted
    /// blob + K_listing on the reply channel.
    ///
    /// `buyer_rev` must correspond to the signer's REV address — the
    /// factory uses `deployerAuthKey` against that vault internally.
    pub fn purchase_listing(
        &self,
        listing_uri: &str,
        buyer_rev: &str,
    ) -> FactoryResult<PurchasePayload> {
        // The standalone paid_transfer_purchase snippet emits only on
        // *return (not a per-nonce string channel). To stay observable
        // for signed deploys, we wrap it inline so the factory's reply
        // fans out to a string channel we control.
        let nonce = fresh_nonce();
        let channel = format!("{PAID_TRANSFER_REPLY_PREFIX}{nonce}");
        let inner = paid_transfer_purchase(listing_uri, buyer_rev);
        // Extract the body (after the top-level `new ... in {`) and
        // retarget the return into both *return and the string channel.
        // Simplest: wrap by composing a Rholang that imports the
        // factory, invokes purchase, and emits on the known channel.
        let term = format!(
            "new return, rl(`rho:registry:lookup`), factoryCh, factoryReply in {{\n  \
             rl!(`{uri}`, *factoryCh) |\n  \
             for (@(_, factory) <- factoryCh) {{\n    \
             @factory!(\"purchase\", {{\"buyer_rev\": {rev}}}, *factoryReply) |\n    \
             for (@reply <- factoryReply) {{\n      \
             return!(reply) |\n      \
             @{reply_ch}!(reply)\n    \
             }}\n  \
             }}\n\
             }}\n",
            uri = listing_uri,
            rev = rho_string(buyer_rev),
            reply_ch = rho_string(&channel),
        );
        let _ = inner; // keep the inner snippet reachable so later refactors can swap in a `_with_nonce` variant
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
