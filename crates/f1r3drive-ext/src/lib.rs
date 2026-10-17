//! `FinderSyncExtensionService` gRPC server.
//!
//! Serves the Stage 0-vendored `generic.FinderSyncExtensionService`
//! on a loopback TCP port — default `127.0.0.1:40411` (external
//! deploy port + 10, mirroring the Java daemon). The macOS Finder
//! Sync extension (shipping from `F1R3FLY-io/f1r3drive-extension`)
//! calls:
//!
//! - `SubmitAction(MenuActionRequest)` — right-click → Change /
//!   Combine on a token file.
//! - `UnlockWalletDirectory(revAddress, privateKey)` — supplies a
//!   signing key for a `LOCKED-REMOTE-REV-*` wallet so the daemon
//!   can promote it and sign transfers from it.
//!
//! The server holds `Arc` handles to the daemon's wallet state
//! (`WalletRegistry`, `KeyStore`, `BillPresenter`) and operates
//! directly on them — no cross-process channel, no state
//! duplication.
//!
//! Transport: plain gRPC, loopback only, no TLS. Fine because the
//! private-key material flows into (never out of) the daemon and
//! the port is only addressable from the local machine. ADR-0001
//! §Finder extension gRPC server flags Unix-domain-socket
//! transport as a v2 fork point.
//!
//! Scope (v1):
//! - `CHANGE`: break one `<denom>-REV.<i>.token` into ten of the
//!   next-smaller denom. Pure client-side presentation; the balance
//!   never changes. Implemented via `BillPresenter::change_denom`.
//! - `COMBINE`: not implemented; returns `ErrorResponse { "..." }`
//!   per ADR.
//! - `UnlockWalletDirectory`: validates key→address derivation,
//!   then `registry.unlock` + `keystore.insert`.

use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use tonic::{transport::Server, Request, Response, Status};
use tracing::{info, warn};

use f1r3drive_client::{ClientError, KeyPair, NodeClient};
use f1r3drive_fs::{BillPresenter, ChangeError, KeyStore, WalletPath};
use f1r3drive_proto::generic::finder_sync_extension_service_server::{
    FinderSyncExtensionService, FinderSyncExtensionServiceServer,
};
use f1r3drive_proto::generic::response::Result as ResponseResult;
use f1r3drive_proto::generic::{
    EmptyResponse, ErrorResponse, MenuActionRequest, MenuActionType, Response as GenericResponse,
    UnlockWalletDirectoryRequest,
};
use f1r3drive_rho::check_balance_snippet;
use f1r3drive_wallet::{BalanceCache, FetchError, RevAddress, WalletRegistry};

/// External TCP endpoint mirroring the Java daemon's default
/// (external deploy port + 10 → `40411`). The macOS extension looks
/// here by convention; exposed as a CLI knob in the daemon for
/// multi-daemon setups.
pub const DEFAULT_EXT_PORT: u16 = 40411;
pub const DEFAULT_EXT_HOST: &str = "127.0.0.1";

/// gRPC service state. Clone-cheap: everything behind `Arc`.
pub struct ExtensionService {
    runtime: tokio::runtime::Handle,
    client: Arc<tokio::sync::Mutex<NodeClient>>,
    registry: Arc<WalletRegistry>,
    cache: Arc<BalanceCache>,
    keys: Arc<KeyStore>,
    presenter: Arc<BillPresenter>,
    /// The daemon's mountpoint. The macOS extension sends paths as
    /// absolute paths of the real filesystem, so we strip this
    /// prefix before classifying them against the wallet tree.
    mountpoint: PathBuf,
}

impl ExtensionService {
    pub fn new(
        runtime: tokio::runtime::Handle,
        client: NodeClient,
        registry: Arc<WalletRegistry>,
        cache: Arc<BalanceCache>,
        keys: Arc<KeyStore>,
        presenter: Arc<BillPresenter>,
        mountpoint: PathBuf,
    ) -> Self {
        Self {
            runtime,
            client: Arc::new(tokio::sync::Mutex::new(client)),
            registry,
            cache,
            keys,
            presenter,
            mountpoint,
        }
    }

    /// Strip the mount prefix off `path` and classify as a wallet
    /// tree node. Returns `None` if the path is outside the mount or
    /// doesn't match a recognized shape.
    fn resolve(&self, raw: &str) -> Option<WalletPath> {
        let abs = PathBuf::from(raw);
        let rel = abs.strip_prefix(&self.mountpoint).ok()?;
        // Reconstruct a leading-slash path for WalletPath::parse,
        // which expects root-anchored paths.
        let mut absolute = PathBuf::from("/");
        for c in rel.components() {
            if let Component::Normal(s) = c {
                absolute.push(s);
            }
        }
        WalletPath::parse(&absolute, &self.registry)
    }

    /// Blocking balance fetch — same shape as `WalletFs::balance_blocking`
    /// but kept local so the ext server has no dep on `WalletFs`
    /// itself.
    fn balance_blocking(&self, address: &RevAddress) -> Result<i64, Status> {
        let address_clone = address.clone();
        let client = self.client.clone();
        let cache = self.cache.clone();
        let outcome = self.runtime.block_on(async move {
            cache
                .get_or_fetch(&address_clone, |want| {
                    let client = client.clone();
                    let b58 = want.to_base58();
                    async move {
                        let snippet = check_balance_snippet(&b58);
                        let mut g = client.lock().await;
                        let r = g
                            .exploratory_deploy(snippet.term(), "", false)
                            .await
                            .map_err(FetchErr::Grpc)?;
                        f1r3drive_rho::decode_balance_reply(&r.pars).map_err(FetchErr::Decode)
                    }
                })
                .await
        });
        match outcome {
            Ok(b) => Ok(b),
            Err(FetchError::Stale { last_known, .. }) => Ok(last_known.balance),
            Err(FetchError::NoCache(e)) => Err(Status::internal(format!("balance fetch: {e:?}"))),
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum FetchErr {
    #[error("gRPC: {0}")]
    Grpc(#[from] ClientError),
    #[error("decode: {0}")]
    Decode(#[from] f1r3drive_rho::BalanceError),
}

/// Spawn the gRPC server on `addr`. Returns a join handle so the
/// caller can keep the task alive for the daemon's lifetime.
pub fn serve(
    service: ExtensionService,
    addr: SocketAddr,
) -> tokio::task::JoinHandle<Result<(), tonic::transport::Error>> {
    info!(%addr, "finder-ext gRPC listening");
    tokio::spawn(async move {
        Server::builder()
            .add_service(FinderSyncExtensionServiceServer::new(service))
            .serve(addr)
            .await
    })
}

fn success_response() -> GenericResponse {
    GenericResponse {
        result: Some(ResponseResult::Success(EmptyResponse {})),
    }
}

fn error_response(msg: impl Into<String>) -> GenericResponse {
    GenericResponse {
        result: Some(ResponseResult::Error(ErrorResponse {
            error_message: msg.into(),
        })),
    }
}

#[tonic::async_trait]
impl FinderSyncExtensionService for ExtensionService {
    async fn submit_action(
        &self,
        request: Request<MenuActionRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let action = MenuActionType::try_from(req.action).unwrap_or(MenuActionType::Change);

        match action {
            MenuActionType::Change => {
                for raw_path in &req.path {
                    let wp = match self.resolve(raw_path) {
                        Some(wp) => wp,
                        None => {
                            return Ok(Response::new(error_response(format!(
                                "path not in a wallet .tokens dir: {raw_path}"
                            ))));
                        }
                    };
                    let WalletPath::TokenFile { address, denom, .. } = wp else {
                        return Ok(Response::new(error_response(format!(
                            "not a *.token file: {raw_path}"
                        ))));
                    };
                    let balance = match self.balance_blocking(&address) {
                        Ok(b) => b.max(0) as u64,
                        Err(e) => {
                            return Ok(Response::new(error_response(format!(
                                "balance fetch failed for {address}: {}",
                                e.message()
                            ))));
                        }
                    };
                    if let Err(e) = self.presenter.change_denom(&address, balance, denom) {
                        return Ok(Response::new(error_response(describe_change_error(&e))));
                    }
                }
                Ok(Response::new(success_response()))
            }
            MenuActionType::Combine => Ok(Response::new(error_response(
                "COMBINE not implemented (ADR-0001 §Non-goals v1)",
            ))),
        }
    }

    async fn unlock_wallet_directory(
        &self,
        request: Request<UnlockWalletDirectoryRequest>,
    ) -> Result<Response<GenericResponse>, Status> {
        let req = request.into_inner();
        let claimed = match RevAddress::parse(&req.rev_address) {
            Ok(a) => a,
            Err(e) => {
                return Ok(Response::new(error_response(format!(
                    "revAddress parse: {e}"
                ))))
            }
        };
        let kp = match KeyPair::from_private_hex(req.private_key.trim()) {
            Ok(k) => k,
            Err(e) => {
                return Ok(Response::new(error_response(format!(
                    "privateKey parse: {e}"
                ))))
            }
        };
        let derived = match RevAddress::from_public_key_bytes(kp.public_key_bytes()) {
            Ok(a) => a,
            Err(e) => {
                return Ok(Response::new(error_response(format!(
                    "pubkey→address: {e}"
                ))))
            }
        };
        if derived != claimed {
            warn!(%claimed, %derived, "unlock rejected: key does not match address");
            return Ok(Response::new(error_response(
                "privateKey does not derive to the claimed revAddress",
            )));
        }
        self.registry.unlock(derived.clone());
        self.keys.insert(derived.clone(), kp);
        info!(address = %derived, "wallet unlocked via Finder extension gRPC");
        Ok(Response::new(success_response()))
    }
}

fn describe_change_error(e: &ChangeError) -> String {
    match e {
        ChangeError::SmallestDenom => "cannot change smallest denomination (1)".to_string(),
        ChangeError::UnknownDenom(d) => format!("denomination {d} is not a known REV denom"),
        ChangeError::NoSuchBill(d) => format!("wallet has no bills of denomination {d} to break"),
    }
}

/// Lightweight path helper used by the extension-side resolve
/// logic. Trims the daemon's mount prefix and leaves the rest
/// absolute. Public for the daemon's own CLI parsing of
/// `--open-url` deep links in Stage 6.
pub fn strip_mount_prefix<'a>(mountpoint: &Path, abs: &'a Path) -> Option<&'a Path> {
    abs.strip_prefix(mountpoint).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALIDATOR_PUBKEY_HEX: &str = "04ffc016579a68050d655d55df4e09f04605164543e257c8e6df10361e6068a5336588e9b355ea859c5ab4285a5ef0efdf62bc28b80320ce99e26bb1607b3ad93d";
    const VALIDATOR_PRIVATE_HEX: &str =
        "5f668a7ee96d944a4494cc947e4005e172d7ab3461ee5538f1f2a45a835e9657";

    fn validator_addr() -> RevAddress {
        let pk = hex::decode(VALIDATOR_PUBKEY_HEX).unwrap();
        RevAddress::from_public_key_bytes(&pk).unwrap()
    }

    #[test]
    fn strip_mount_prefix_works() {
        let mp = Path::new("/tmp/mnt");
        let abs = Path::new("/tmp/mnt/1111Addr/.tokens/1000-REV.0.token");
        assert_eq!(
            strip_mount_prefix(mp, abs),
            Some(Path::new("1111Addr/.tokens/1000-REV.0.token")),
        );
    }

    #[test]
    fn strip_mount_prefix_rejects_outside() {
        let mp = Path::new("/tmp/mnt");
        let abs = Path::new("/elsewhere/notes.txt");
        assert_eq!(strip_mount_prefix(mp, abs), None);
    }

    #[test]
    fn describe_change_error_mentions_denom() {
        assert_eq!(
            describe_change_error(&ChangeError::SmallestDenom),
            "cannot change smallest denomination (1)",
        );
        assert!(describe_change_error(&ChangeError::NoSuchBill(100)).contains("100"));
        assert!(describe_change_error(&ChangeError::UnknownDenom(42)).contains("42"));
    }

    #[test]
    fn success_and_error_response_shapes() {
        let ok = success_response();
        assert!(matches!(ok.result, Some(ResponseResult::Success(_))));
        let err = error_response("oops");
        match err.result {
            Some(ResponseResult::Error(ErrorResponse { error_message })) => {
                assert_eq!(error_message, "oops");
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn validator_derive_round_trip_for_unlock_sanity() {
        // Not an RPC test; just confirms the derivation that
        // `unlock_wallet_directory` relies on.
        let kp = KeyPair::from_private_hex(VALIDATOR_PRIVATE_HEX).unwrap();
        let derived = RevAddress::from_public_key_bytes(kp.public_key_bytes()).unwrap();
        assert_eq!(derived, validator_addr());
    }
}
