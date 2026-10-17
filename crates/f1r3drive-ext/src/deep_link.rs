//! `f1r3drive://` URL-scheme handling.
//!
//! One scheme, one action for v1:
//!
//! ```text
//! f1r3drive://unlock?revAddress=<base58>&privateKey=<hex>
//! ```
//!
//! The macOS app bundle's `Info.plist` can register this scheme at
//! Finder-extension installation time (Stage 7). From the Rust side,
//! the daemon accepts `--open-url <url>` as a *one-shot CLI mode*:
//! parse the URL, open a short-lived gRPC client to the local
//! daemon's `FinderSyncExtensionService` endpoint, forward the
//! parsed arguments as `UnlockWalletDirectory`, print the result,
//! and exit. The already-running daemon handles the unlock side
//! effects.
//!
//! Hand-rolled parsing instead of pulling the `url` crate because
//! the surface is tiny and the dep graph for `url` (unicode-ident,
//! percent-encoding, etc.) is bigger than our needs.

use thiserror::Error;
use tonic::transport::Channel;

use f1r3drive_proto::generic::finder_sync_extension_service_client::FinderSyncExtensionServiceClient;
use f1r3drive_proto::generic::{response::Result as ResponseResult, UnlockWalletDirectoryRequest};

use crate::{DEFAULT_EXT_HOST, DEFAULT_EXT_PORT};

pub const SCHEME: &str = "f1r3drive";
pub const UNLOCK_ACTION: &str = "unlock";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DeepLinkError {
    #[error("URL must start with `{SCHEME}://`")]
    BadScheme,
    #[error("unknown action {0:?}; expected {UNLOCK_ACTION:?}")]
    UnknownAction(String),
    #[error("missing required query parameter {0:?}")]
    MissingParam(&'static str),
    #[error("duplicate query parameter {0:?}")]
    DuplicateParam(&'static str),
}

/// Parsed `f1r3drive://unlock?revAddress=…&privateKey=…`.
#[derive(Debug, PartialEq, Eq)]
pub struct UnlockLink {
    pub rev_address: String,
    pub private_key: String,
}

impl UnlockLink {
    pub fn parse(url: &str) -> Result<Self, DeepLinkError> {
        let body = url
            .strip_prefix(&format!("{SCHEME}://"))
            .ok_or(DeepLinkError::BadScheme)?;
        let (action, query) = body.split_once('?').unwrap_or((body, ""));
        if action != UNLOCK_ACTION {
            return Err(DeepLinkError::UnknownAction(action.to_string()));
        }

        let mut rev_address: Option<String> = None;
        let mut private_key: Option<String> = None;
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            match k {
                "revAddress" => {
                    if rev_address.is_some() {
                        return Err(DeepLinkError::DuplicateParam("revAddress"));
                    }
                    rev_address = Some(percent_decode(v));
                }
                "privateKey" => {
                    if private_key.is_some() {
                        return Err(DeepLinkError::DuplicateParam("privateKey"));
                    }
                    private_key = Some(percent_decode(v));
                }
                _ => {
                    // Unknown params are tolerated — the Finder
                    // extension may grow more fields later; we don't
                    // want to be a protocol gatekeeper.
                }
            }
        }

        Ok(Self {
            rev_address: rev_address.ok_or(DeepLinkError::MissingParam("revAddress"))?,
            private_key: private_key.ok_or(DeepLinkError::MissingParam("privateKey"))?,
        })
    }
}

/// Minimal `%NN` percent-decoder. Doesn't need to handle unicode or
/// `+` → space (REV addresses are ASCII base58, private keys are
/// ASCII hex; neither hits the odd shapes).
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3]) {
                if let Ok(byte) = u8::from_str_radix(hex, 16) {
                    out.push(byte);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Result of forwarding an `UnlockWalletDirectory` call to a daemon.
#[derive(Debug)]
pub enum UnlockOutcome {
    Success,
    DaemonError(String),
    Transport(tonic::transport::Error),
    Rpc(tonic::Status),
}

/// One-shot CLI mode: open a gRPC client to the daemon's extension
/// endpoint, forward the parsed `UnlockLink` as
/// `UnlockWalletDirectory`, return the daemon's reply.
pub async fn forward_unlock(link: UnlockLink, host: &str, port: u16) -> UnlockOutcome {
    let endpoint = format!("http://{host}:{port}");
    let channel = match Channel::from_shared(endpoint)
        .expect("static endpoint parses")
        .connect()
        .await
    {
        Ok(c) => c,
        Err(e) => return UnlockOutcome::Transport(e),
    };
    let mut client = FinderSyncExtensionServiceClient::new(channel);
    let req = UnlockWalletDirectoryRequest {
        rev_address: link.rev_address,
        private_key: link.private_key,
    };
    match client.unlock_wallet_directory(req).await {
        Ok(resp) => match resp.into_inner().result {
            Some(ResponseResult::Success(_)) => UnlockOutcome::Success,
            Some(ResponseResult::Error(e)) => UnlockOutcome::DaemonError(e.error_message),
            None => UnlockOutcome::DaemonError("daemon returned empty Response".into()),
        },
        Err(s) => UnlockOutcome::Rpc(s),
    }
}

/// Convenience that uses [`DEFAULT_EXT_HOST`] / [`DEFAULT_EXT_PORT`].
pub async fn forward_unlock_default(link: UnlockLink) -> UnlockOutcome {
    forward_unlock(link, DEFAULT_EXT_HOST, DEFAULT_EXT_PORT).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical_unlock_url() {
        let link = UnlockLink::parse("f1r3drive://unlock?revAddress=1111Atah&privateKey=5f668a7e")
            .unwrap();
        assert_eq!(link.rev_address, "1111Atah");
        assert_eq!(link.private_key, "5f668a7e");
    }

    #[test]
    fn parses_in_either_param_order() {
        let a = UnlockLink::parse("f1r3drive://unlock?revAddress=A&privateKey=B").unwrap();
        let b = UnlockLink::parse("f1r3drive://unlock?privateKey=B&revAddress=A").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_wrong_scheme() {
        assert_eq!(
            UnlockLink::parse("http://unlock?revAddress=A&privateKey=B"),
            Err(DeepLinkError::BadScheme),
        );
    }

    #[test]
    fn rejects_unknown_action() {
        assert_eq!(
            UnlockLink::parse("f1r3drive://listen?revAddress=A&privateKey=B"),
            Err(DeepLinkError::UnknownAction("listen".into())),
        );
    }

    #[test]
    fn requires_both_params() {
        assert_eq!(
            UnlockLink::parse("f1r3drive://unlock?revAddress=A"),
            Err(DeepLinkError::MissingParam("privateKey")),
        );
        assert_eq!(
            UnlockLink::parse("f1r3drive://unlock?privateKey=B"),
            Err(DeepLinkError::MissingParam("revAddress")),
        );
    }

    #[test]
    fn rejects_duplicates() {
        assert_eq!(
            UnlockLink::parse("f1r3drive://unlock?revAddress=A&revAddress=B&privateKey=K"),
            Err(DeepLinkError::DuplicateParam("revAddress")),
        );
    }

    #[test]
    fn tolerates_unknown_params() {
        let link = UnlockLink::parse("f1r3drive://unlock?revAddress=A&privateKey=B&source=finder")
            .unwrap();
        assert_eq!(link.rev_address, "A");
        assert_eq!(link.private_key, "B");
    }

    #[test]
    fn percent_decodes_values() {
        // `+` isn't decoded (not needed for our address/key shapes),
        // but `%2B` → `+` works.
        let link =
            UnlockLink::parse("f1r3drive://unlock?revAddress=A%2BB&privateKey=C%3DD").unwrap();
        assert_eq!(link.rev_address, "A+B");
        assert_eq!(link.private_key, "C=D");
    }
}
