//! `WalletFs` — the `--mount-mode=wallets` filesystem.
//!
//! A synthetic tree whose entries are wallet directories, each
//! containing a `.tokens/` child whose readdir emits one zero-byte
//! `.token` file per bill in the on-chain balance. Pure read side
//! for Stage 3; `rename`-driven transfers land in Stage 4.
//!
//! Shape (ADR-0001 §Directory and file naming):
//!
//! ```text
//! /
//! ├── LOCKED-REMOTE-REV-<addr>/          # tracked but locked; empty
//! └── <addr>/                            # unlocked
//!     └── .tokens/
//!         ├── 1000000000000000000-REV.0.token
//!         ├── 100000000-REV.0.token
//!         ├── 100000000-REV.1.token
//!         └── …
//! ```
//!
//! The `.token` files are entirely synthetic — `open`/`read`/`write`/
//! `truncate` return `Ok(0)` with no side effects, matching
//! `TokenFile.java` on the Java daemon. Finder renders them as
//! zero-byte files you can only drag across wallets; the actual
//! transfer happens in Stage 4's `rename` implementation.

use std::path::{Component, Path};
use std::sync::Arc;
use std::time::SystemTime;

use libfuse_t_rs::{
    DirEntry as FtDirEntry, FileAttr as FtFileAttr, FileKind, Filesystem, FsError as FtFsError,
    FsResult as FtFsResult,
};
use tokio::runtime::Handle;
use tokio::sync::Mutex;
use tracing::{debug, trace, warn};

use f1r3drive_client::{ClientError, NodeClient};
use f1r3drive_rho::{check_balance_snippet, decode_balance_reply, BalanceError};
use f1r3drive_wallet::{
    decompose, BalanceCache, DenomBill, FetchError, LockState, RevAddress, WalletRegistry,
    WalletState,
};
use thiserror::Error;

/// Prefix used by the directory name of a tracked-but-locked wallet.
pub const LOCKED_PREFIX: &str = "LOCKED-REMOTE-REV-";
/// Name of the per-wallet `.tokens` subdirectory.
pub const TOKENS_DIR: &str = ".tokens";
/// Suffix every synthetic token file carries.
pub const TOKEN_SUFFIX: &str = ".token";
/// Infix of a token filename, after the denomination.
const DENOM_INFIX: &str = "-REV";

/// Static tuning knobs. Timestamp granularity is 1s; the mount
/// doesn't expose atime/mtime for synthetic entries, so these all
/// default to the Unix epoch.
#[derive(Debug, Clone, Default)]
pub struct WalletFsConfig {
    pub display_uid: u32,
    pub display_gid: u32,
}

/// FUSE-side wallet surface.
pub struct WalletFs {
    runtime: Handle,
    client: Arc<Mutex<NodeClient>>,
    registry: Arc<WalletRegistry>,
    cache: Arc<BalanceCache>,
    config: WalletFsConfig,
}

impl WalletFs {
    pub fn new(
        runtime: Handle,
        client: NodeClient,
        registry: Arc<WalletRegistry>,
        cache: Arc<BalanceCache>,
        config: WalletFsConfig,
    ) -> Self {
        Self {
            runtime,
            client: Arc::new(Mutex::new(client)),
            registry,
            cache,
            config,
        }
    }

    /// Blocking balance fetch for the FUSE callback thread. Hits the
    /// cache first; on miss, submits an `exploratory_deploy` of the
    /// `rho:vault:system → balance` snippet. On error we serve stale
    /// if we have any; otherwise surface `EIO`.
    fn balance_blocking(&self, address: &RevAddress) -> FtFsResult<i64> {
        let address = address.clone();
        let client = self.client.clone();
        let cache = self.cache.clone();

        let outcome = self.runtime.block_on(async move {
            cache
                .get_or_fetch(&address, |want| {
                    let client = client.clone();
                    let b58 = want.to_base58();
                    async move {
                        let snippet = check_balance_snippet(&b58);
                        let mut guard = client.lock().await;
                        let reply = guard
                            .exploratory_deploy(snippet.term(), "", false)
                            .await
                            .map_err(BalanceFetchError::Grpc)?;
                        decode_balance_reply(&reply.pars).map_err(BalanceFetchError::Decode)
                    }
                })
                .await
        });

        match outcome {
            Ok(b) => Ok(b),
            Err(FetchError::Stale { last_known, err }) => {
                warn!(
                    ?err,
                    balance = last_known.balance,
                    "balance refetch failed; serving stale"
                );
                Ok(last_known.balance)
            }
            Err(FetchError::NoCache(err)) => {
                warn!(
                    ?err,
                    "balance fetch failed and nothing cached; returning EIO"
                );
                Err(FtFsError::Io)
            }
        }
    }

    fn now_attr_file(&self) -> FtFileAttr {
        FtFileAttr {
            kind: FileKind::Regular,
            perm: 0o444,
            size: 0,
            nlink: 1,
            uid: self.config.display_uid,
            gid: self.config.display_gid,
            atime: SystemTime::UNIX_EPOCH,
            mtime: SystemTime::UNIX_EPOCH,
            ctime: SystemTime::UNIX_EPOCH,
            blocks: None,
            blksize: 4096,
        }
    }

    fn now_attr_dir(&self) -> FtFileAttr {
        FtFileAttr::dir(self.config.display_uid, self.config.display_gid)
    }
}

/// What a kernel-presented path resolves to inside the wallet tree.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum WalletPath {
    /// `/`
    Root,
    /// `/LOCKED-REMOTE-REV-<addr>` for a tracked, un-unlocked wallet.
    LockedWallet(RevAddress),
    /// `/<addr>` for a tracked, unlocked wallet.
    UnlockedWallet(RevAddress),
    /// `/<addr>/.tokens` — synthetic token-directory inside an
    /// unlocked wallet.
    TokensDir(RevAddress),
    /// `/<addr>/.tokens/<denom>-REV.<index>.token`.
    TokenFile {
        address: RevAddress,
        denom: u64,
        index: u64,
    },
}

impl WalletPath {
    /// Classify a kernel path against the current registry. Returns
    /// `None` for paths that don't match any wallet-tree shape or
    /// whose first segment names a wallet we don't track.
    pub fn parse(path: &Path, registry: &WalletRegistry) -> Option<Self> {
        let mut comps = path.components();
        // Every absolute path starts with RootDir in `std::path`.
        if comps.next() != Some(Component::RootDir) {
            return None;
        }
        let segs: Vec<&str> = comps
            .map(|c| match c {
                Component::Normal(s) => s.to_str(),
                _ => None,
            })
            .collect::<Option<Vec<_>>>()?;

        match segs.as_slice() {
            [] => Some(Self::Root),
            [first] => classify_wallet_segment(first, registry).map(|(addr, locked)| {
                if locked {
                    Self::LockedWallet(addr)
                } else {
                    Self::UnlockedWallet(addr)
                }
            }),
            [first, TOKENS_DIR] => {
                let (addr, locked) = classify_wallet_segment(first, registry)?;
                if locked {
                    None // tokens dir doesn't exist on locked wallets
                } else {
                    Some(Self::TokensDir(addr))
                }
            }
            [first, TOKENS_DIR, filename] => {
                let (addr, locked) = classify_wallet_segment(first, registry)?;
                if locked {
                    return None;
                }
                let (denom, index) = parse_token_name(filename)?;
                Some(Self::TokenFile {
                    address: addr,
                    denom,
                    index,
                })
            }
            _ => None,
        }
    }
}

/// Classify a first-level path segment. Returns `Some((addr,
/// is_locked))` iff `segment` names a wallet currently in the
/// registry AND the lock state in the name agrees with the
/// registry's belief. A locked-named segment whose address is
/// actually unlocked (or vice versa) returns `None` — the kernel
/// shouldn't be asking about that path, and treating a mismatch as
/// ENOENT keeps the state surface honest.
fn classify_wallet_segment(segment: &str, registry: &WalletRegistry) -> Option<(RevAddress, bool)> {
    if let Some(stripped) = segment.strip_prefix(LOCKED_PREFIX) {
        let addr = RevAddress::parse(stripped).ok()?;
        let state = registry.get(&addr)?;
        if state.lock_state == LockState::Locked {
            Some((addr, true))
        } else {
            None
        }
    } else {
        let addr = RevAddress::parse(segment).ok()?;
        let state = registry.get(&addr)?;
        if state.lock_state == LockState::Unlocked {
            Some((addr, false))
        } else {
            None
        }
    }
}

/// `<denom>-REV.<index>.token` → `(denom, index)`. Returns `None` if
/// the shape doesn't match, if the denomination isn't one of the 19
/// known ones, or if either integer fails to parse.
pub fn parse_token_name(name: &str) -> Option<(u64, u64)> {
    let stripped = name.strip_suffix(TOKEN_SUFFIX)?;
    let (lhs, idx_str) = stripped.rsplit_once('.')?;
    let denom_str = lhs.strip_suffix(DENOM_INFIX)?;
    let denom: u64 = denom_str.parse().ok()?;
    let index: u64 = idx_str.parse().ok()?;
    if !f1r3drive_wallet::DENOMINATIONS.contains(&denom) {
        return None;
    }
    Some((denom, index))
}

/// Inverse of [`parse_token_name`].
pub fn format_token_name(denom: u64, index: u64) -> String {
    format!("{denom}{DENOM_INFIX}.{index}{TOKEN_SUFFIX}")
}

/// Build the one-level directory listing a wallet directory presents.
/// Returns `Vec<DirEntry>` for both the root and the per-wallet
/// case, so the FUSE `readdir` just dispatches to one of these.
fn root_entries(registry: &WalletRegistry) -> Vec<FtDirEntry> {
    let mut entries: Vec<FtDirEntry> = registry.snapshot().into_iter().map(wallet_entry).collect();
    // Deterministic order so the user's view of the tree doesn't
    // churn across readdir calls.
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    entries
}

fn wallet_entry(state: WalletState) -> FtDirEntry {
    let name = match state.lock_state {
        LockState::Locked => format!("{LOCKED_PREFIX}{}", state.address),
        LockState::Unlocked => state.address.to_base58(),
    };
    FtDirEntry::new(name, FileKind::Directory)
}

/// Decompose `balance` into denomination bills and flatten into one
/// `DirEntry` per bill, naming each `<denom>-REV.<idx>.token`.
fn bills_to_entries(balance: u64) -> Vec<FtDirEntry> {
    decompose(balance)
        .into_iter()
        .flat_map(|DenomBill { denom, count }| {
            (0..count)
                .map(move |idx| FtDirEntry::new(format_token_name(denom, idx), FileKind::Regular))
        })
        .collect()
}

/// Internal fetch-error enum. Flows through `BalanceCache::get_or_fetch`'s
/// generic error channel and is only ever surfaced for logging.
#[derive(Debug, Error)]
enum BalanceFetchError {
    #[error("gRPC: {0}")]
    Grpc(#[from] ClientError),
    #[error("decode: {0}")]
    Decode(#[from] BalanceError),
}

impl Filesystem for WalletFs {
    fn init(&self) {
        tracing::info!("WalletFs mounted ({} tracked)", self.registry.len());
    }

    fn getattr(&self, path: &Path) -> FtFsResult<FtFileAttr> {
        trace!(?path, "getattr");
        match WalletPath::parse(path, &self.registry) {
            Some(WalletPath::Root)
            | Some(WalletPath::LockedWallet(_))
            | Some(WalletPath::UnlockedWallet(_))
            | Some(WalletPath::TokensDir(_)) => Ok(self.now_attr_dir()),
            Some(WalletPath::TokenFile { .. }) => Ok(self.now_attr_file()),
            None => Err(FtFsError::NotFound),
        }
    }

    fn readdir(&self, path: &Path) -> FtFsResult<Vec<FtDirEntry>> {
        trace!(?path, "readdir");
        match WalletPath::parse(path, &self.registry) {
            Some(WalletPath::Root) => Ok(root_entries(&self.registry)),
            Some(WalletPath::UnlockedWallet(_)) => {
                // Every unlocked wallet shows exactly one child, the
                // `.tokens` directory.
                Ok(vec![FtDirEntry::new(TOKENS_DIR, FileKind::Directory)])
            }
            Some(WalletPath::LockedWallet(_)) => Ok(Vec::new()),
            Some(WalletPath::TokensDir(addr)) => {
                let balance = self.balance_blocking(&addr)?;
                let bal_u = balance.max(0) as u64;
                debug!(address = %addr, balance, "readdir .tokens");
                Ok(bills_to_entries(bal_u))
            }
            Some(WalletPath::TokenFile { .. }) | None => Err(FtFsError::NotADirectory),
        }
    }

    fn read(&self, path: &Path, _offset: u64, _size: usize, _fh: u64) -> FtFsResult<Vec<u8>> {
        // Match TokenFile.java: read on a token file is a no-op
        // returning zero bytes. open/release are no-ops too (via
        // the trait defaults).
        if matches!(
            WalletPath::parse(path, &self.registry),
            Some(WalletPath::TokenFile { .. })
        ) {
            Ok(Vec::new())
        } else {
            Err(FtFsError::NotFound)
        }
    }

    fn open(&self, path: &Path, _flags: i32) -> FtFsResult<u64> {
        if matches!(
            WalletPath::parse(path, &self.registry),
            Some(WalletPath::TokenFile { .. })
        ) {
            Ok(0)
        } else {
            Err(FtFsError::NotFound)
        }
    }

    fn write(&self, path: &Path, _offset: u64, data: &[u8], _fh: u64) -> FtFsResult<usize> {
        // Writes to a token file are swallowed to keep callers like
        // `cp` happy; everywhere else is EPERM.
        if matches!(
            WalletPath::parse(path, &self.registry),
            Some(WalletPath::TokenFile { .. })
        ) {
            Ok(data.len())
        } else {
            Err(FtFsError::PermissionDenied)
        }
    }

    fn truncate(&self, path: &Path, _size: u64) -> FtFsResult<()> {
        if matches!(
            WalletPath::parse(path, &self.registry),
            Some(WalletPath::TokenFile { .. })
        ) {
            Ok(())
        } else {
            Err(FtFsError::PermissionDenied)
        }
    }

    fn chmod(&self, _path: &Path, _mode: u32) -> FtFsResult<()> {
        Err(FtFsError::PermissionDenied)
    }

    fn create(&self, _path: &Path, _mode: u32, _flags: i32) -> FtFsResult<u64> {
        Err(FtFsError::PermissionDenied)
    }

    fn mkdir(&self, _path: &Path, _mode: u32) -> FtFsResult<()> {
        Err(FtFsError::PermissionDenied)
    }

    fn unlink(&self, _path: &Path) -> FtFsResult<()> {
        Err(FtFsError::PermissionDenied)
    }

    fn rmdir(&self, _path: &Path) -> FtFsResult<()> {
        Err(FtFsError::PermissionDenied)
    }

    fn rename(&self, _from: &Path, _to: &Path) -> FtFsResult<()> {
        // Transfers land in Stage 4. Until then any rename is
        // rejected with EINVAL — matches the ADR table for v1
        // "rename within same .tokens/" (and conservatively rejects
        // cross-wallet renames too; the Stage 4 implementation will
        // narrow this to only the transfer case).
        Err(FtFsError::InvalidArgument)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALIDATOR_PUBKEY_HEX: &str = "04ffc016579a68050d655d55df4e09f04605164543e257c8e6df10361e6068a5336588e9b355ea859c5ab4285a5ef0efdf62bc28b80320ce99e26bb1607b3ad93d";

    fn validator_addr() -> RevAddress {
        let pk = hex::decode(VALIDATOR_PUBKEY_HEX).unwrap();
        RevAddress::from_public_key_bytes(&pk).unwrap()
    }

    fn fake_addr(seed: u8) -> RevAddress {
        let eth = format!("{:040x}", seed as u128);
        RevAddress::from_eth_address(&eth).unwrap()
    }

    fn registry_with(locked: Vec<RevAddress>, unlocked: Vec<RevAddress>) -> WalletRegistry {
        let r = WalletRegistry::new();
        for a in locked {
            r.track(a);
        }
        for a in unlocked {
            r.unlock(a);
        }
        r
    }

    #[test]
    fn parse_root() {
        let r = WalletRegistry::new();
        assert_eq!(
            WalletPath::parse(Path::new("/"), &r),
            Some(WalletPath::Root),
        );
    }

    #[test]
    fn parse_unlocked_wallet() {
        let addr = validator_addr();
        let r = registry_with(vec![], vec![addr.clone()]);
        let p = format!("/{}", addr);
        assert_eq!(
            WalletPath::parse(Path::new(&p), &r),
            Some(WalletPath::UnlockedWallet(addr)),
        );
    }

    #[test]
    fn parse_locked_wallet() {
        let addr = validator_addr();
        let r = registry_with(vec![addr.clone()], vec![]);
        let p = format!("/{LOCKED_PREFIX}{}", addr);
        assert_eq!(
            WalletPath::parse(Path::new(&p), &r),
            Some(WalletPath::LockedWallet(addr)),
        );
    }

    #[test]
    fn parse_locked_name_but_actually_unlocked_in_registry_is_none() {
        // The kernel asks about a path that advertises "locked" but
        // the registry says "unlocked". We treat that as ENOENT so
        // the state surface doesn't lie.
        let addr = validator_addr();
        let r = registry_with(vec![], vec![addr.clone()]);
        let p = format!("/{LOCKED_PREFIX}{}", addr);
        assert_eq!(WalletPath::parse(Path::new(&p), &r), None);
    }

    #[test]
    fn parse_unknown_wallet_is_none() {
        let addr = validator_addr();
        let r = WalletRegistry::new();
        let p = format!("/{}", addr);
        assert_eq!(WalletPath::parse(Path::new(&p), &r), None);
    }

    #[test]
    fn parse_tokens_dir() {
        let addr = validator_addr();
        let r = registry_with(vec![], vec![addr.clone()]);
        let p = format!("/{}/.tokens", addr);
        assert_eq!(
            WalletPath::parse(Path::new(&p), &r),
            Some(WalletPath::TokensDir(addr)),
        );
    }

    #[test]
    fn parse_tokens_dir_under_locked_wallet_is_none() {
        let addr = validator_addr();
        let r = registry_with(vec![addr.clone()], vec![]);
        let p = format!("/{LOCKED_PREFIX}{}/.tokens", addr);
        assert_eq!(WalletPath::parse(Path::new(&p), &r), None);
    }

    #[test]
    fn parse_token_file() {
        let addr = validator_addr();
        let r = registry_with(vec![], vec![addr.clone()]);
        let p = format!("/{}/.tokens/1000-REV.3.token", addr);
        assert_eq!(
            WalletPath::parse(Path::new(&p), &r),
            Some(WalletPath::TokenFile {
                address: addr,
                denom: 1_000,
                index: 3,
            }),
        );
    }

    #[test]
    fn parse_token_file_rejects_unknown_denom() {
        let addr = validator_addr();
        let r = registry_with(vec![], vec![addr.clone()]);
        let p = format!("/{}/.tokens/42-REV.0.token", addr); // 42 not in denominations
        assert_eq!(WalletPath::parse(Path::new(&p), &r), None);
    }

    #[test]
    fn parse_rejects_deep_paths() {
        let addr = validator_addr();
        let r = registry_with(vec![], vec![addr.clone()]);
        let p = format!("/{}/.tokens/1000-REV.0.token/extra", addr);
        assert_eq!(WalletPath::parse(Path::new(&p), &r), None);
    }

    #[test]
    fn token_name_round_trip() {
        for &denom in &f1r3drive_wallet::DENOMINATIONS {
            for index in [0u64, 1, 7, 100] {
                let name = format_token_name(denom, index);
                assert_eq!(parse_token_name(&name), Some((denom, index)));
            }
        }
    }

    #[test]
    fn parse_token_name_shape_errors() {
        assert_eq!(parse_token_name("1000.0.token"), None); // missing -REV
        assert_eq!(parse_token_name("1000-REV.0.rev"), None); // wrong suffix
        assert_eq!(parse_token_name("abc-REV.0.token"), None); // non-numeric denom
        assert_eq!(parse_token_name("1000-REV.abc.token"), None); // non-numeric idx
    }

    #[test]
    fn root_entries_sorted() {
        let a = fake_addr(1);
        let b = fake_addr(2);
        let c = fake_addr(3);
        // Mix lock states.
        let r = registry_with(vec![a.clone(), c.clone()], vec![b.clone()]);
        let entries = root_entries(&r);
        let names: Vec<_> = entries.iter().map(|e| e.name.clone()).collect();
        // Each entry present exactly once.
        assert_eq!(entries.len(), 3);
        // Deterministic sort: alphabetical.
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(names, sorted);
    }

    #[test]
    fn bills_to_entries_matches_decomposition() {
        // 1234: 1×1000 + 2×100 + 3×10 + 4×1 = 10 bills total.
        let entries = bills_to_entries(1234);
        assert_eq!(entries.len(), 10);

        // Verify names + ordering of each denom's run.
        let names: Vec<_> = entries.iter().map(|e| e.name.clone()).collect();
        assert_eq!(names[0], "1000-REV.0.token");
        assert_eq!(names[1], "100-REV.0.token");
        assert_eq!(names[2], "100-REV.1.token");
        assert_eq!(names[3], "10-REV.0.token");
        assert_eq!(names[6], "1-REV.0.token");
        assert_eq!(names[9], "1-REV.3.token");
    }

    #[test]
    fn bills_to_entries_zero_balance_empty() {
        assert!(bills_to_entries(0).is_empty());
    }
}
