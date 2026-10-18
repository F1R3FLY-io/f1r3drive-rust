//! `ExtensionFs` — the `--mount-mode=extension` filesystem.
//!
//! Per-user folders named by uncompressed secp256k1 pubkey hex (130
//! chars). Non-owners see other users' folders exist but
//! `readdir` on them returns empty — the ACL is daemon-enforced, not
//! chain-enforced. See `docs/architecture/ADR-0002-extension-design.md`.
//!
//! This slice (3) is the skeleton: path parsing + ACL + readdir on
//! the pubkey + fixed-contract-template subfolder set. All file ops
//! stub out — content writes and reads land in slice 4 once the
//! `f1r3drive-crypto` envelope primitives are wired to the on-chain
//! `Fs` agent.
//!
//! Shape:
//!
//! ```text
//! /
//! ├── <my-pubkey-130hex>/              daemon's own identity folder
//! │   ├── .tokens/<denom>-REV.<i>.token
//! │   ├── Paid transfer/               factory template
//! │   └── <plaintext-filenames>        (slice 4+)
//! └── <other-pubkey-130hex>/           tracked foreign identities;
//!                                      readdir returns empty for us
//! ```
//!
//! The daemon learns about foreign pubkey folders via
//! `--track-pubkey <hex>` (repeatable). Uuid-folders for paid
//! transfer land in slice 7.

use std::path::{Component, Path};
use std::sync::Arc;
use std::time::SystemTime;

use libfuse_t_rs::{
    DirEntry as FtDirEntry, FileAttr as FtFileAttr, FileKind, Filesystem, FsError as FtFsError,
    FsResult as FtFsResult,
};
use tracing::trace;

use f1r3drive_identity::Identity;

/// Length of a pubkey-folder name in hex characters.
///
/// 65-byte uncompressed secp256k1 pubkey (`0x04 || x || y`) encoded
/// as 2 hex chars per byte = 130 chars. The folder name is always
/// lowercase; the parser accepts mixed-case for robustness and
/// normalises internally.
pub const PUBKEY_HEX_LEN: usize = 130;

/// Name of the per-wallet token subtree (unchanged from ADR-0001).
pub const TOKENS_DIR: &str = ".tokens";

/// Name of the fixed Paid-transfer factory folder.
pub const PAID_TRANSFER_DIR: &str = "Paid transfer";

/// Static set of contract-template subfolder names rendered inside
/// every pubkey folder. v1 has exactly one; slice 7 extends.
const CONTRACT_TEMPLATES: &[&str] = &[PAID_TRANSFER_DIR];

/// Tunables for attribute display + ACL interaction.
#[derive(Debug, Clone, Default)]
pub struct ExtensionFsConfig {
    pub display_uid: u32,
    pub display_gid: u32,
}

/// FUSE-side implementation of ADR-0002's extension mount.
pub struct ExtensionFs {
    identity: Arc<Identity>,
    /// Foreign pubkey folders to render in `readdir /`. Lowercase hex
    /// (130 chars each); the daemon never serves readdir CONTENT for
    /// these — only their existence.
    tracked: Vec<String>,
    config: ExtensionFsConfig,
}

impl ExtensionFs {
    pub fn new(
        identity: Arc<Identity>,
        tracked_pubkeys: Vec<String>,
        config: ExtensionFsConfig,
    ) -> Self {
        // Normalise tracked pubkeys to lowercase, dedup, and drop the
        // daemon's own pubkey (which we always render separately).
        let own = identity.pubkey_hex().to_lowercase();
        let mut tracked: Vec<String> = tracked_pubkeys
            .into_iter()
            .map(|s| s.to_lowercase())
            .filter(|s| s != &own)
            .collect();
        tracked.sort();
        tracked.dedup();
        Self {
            identity,
            tracked,
            config,
        }
    }

    fn own_pubkey(&self) -> &str {
        self.identity.pubkey_hex()
    }

    fn is_own(&self, pubkey_hex_lower: &str) -> bool {
        pubkey_hex_lower == self.own_pubkey()
    }

    /// Does `pubkey_hex_lower` name a folder the daemon is tracking?
    /// Includes the daemon's own identity.
    fn is_known(&self, pubkey_hex_lower: &str) -> bool {
        self.is_own(pubkey_hex_lower)
            || self
                .tracked
                .binary_search(&pubkey_hex_lower.to_string())
                .is_ok()
    }

    fn attr_dir(&self) -> FtFileAttr {
        FtFileAttr::dir(self.config.display_uid, self.config.display_gid)
    }

    fn attr_file_empty(&self) -> FtFileAttr {
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
}

/// Resolved shape of a kernel-presented path against this filesystem.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ExtPath {
    /// `/`
    Root,
    /// `/<pubkey>/` — our own identity. ACL-wise, readable.
    OwnFolder,
    /// `/<pubkey>/` — a tracked foreign identity. Readdir returns
    /// empty; getattr lies cleanly as a directory.
    ForeignFolder(String),
    /// `/<my-pubkey>/.tokens/`
    OwnTokensDir,
    /// `/<my-pubkey>/.tokens/<denom>-REV.<idx>.token`
    OwnTokenFile { denom: u64, index: u64 },
    /// `/<my-pubkey>/Paid transfer/`
    OwnContractTemplateDir(&'static str),
    /// `/<my-pubkey>/<file>` where `<file>` isn't a known subfolder —
    /// a user content file (slice 4+ decrypts and reads).
    OwnFileEntry(String),
}

impl ExtPath {
    /// Classify `path` against the daemon's identity + tracked set.
    /// Returns `None` if the path doesn't match any known shape; the
    /// caller translates `None` to `ENOENT`.
    pub fn parse(path: &Path, fs: &ExtensionFs) -> Option<Self> {
        let mut comps = path.components();
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

            [first] => {
                let name = first.to_lowercase();
                if !is_pubkey_hex(&name) {
                    return None;
                }
                if fs.is_own(&name) {
                    Some(Self::OwnFolder)
                } else if fs.is_known(&name) {
                    Some(Self::ForeignFolder(name))
                } else {
                    None
                }
            }

            [first, second] => {
                let folder = first.to_lowercase();
                if !is_pubkey_hex(&folder) || !fs.is_own(&folder) {
                    // Only the owner's own folder has subshapes
                    // visible to the daemon.
                    return None;
                }
                match *second {
                    TOKENS_DIR => Some(Self::OwnTokensDir),
                    name if is_contract_template(name).is_some() => Some(
                        Self::OwnContractTemplateDir(is_contract_template(name).unwrap()),
                    ),
                    name => Some(Self::OwnFileEntry(name.to_string())),
                }
            }

            [first, TOKENS_DIR, token_name] => {
                let folder = first.to_lowercase();
                if !is_pubkey_hex(&folder) || !fs.is_own(&folder) {
                    return None;
                }
                let (denom, index) = parse_token_filename(token_name)?;
                Some(Self::OwnTokenFile { denom, index })
            }

            _ => None,
        }
    }
}

fn is_pubkey_hex(s: &str) -> bool {
    s.len() == PUBKEY_HEX_LEN && s.chars().all(|c| c.is_ascii_hexdigit()) && s.starts_with("04")
}

fn is_contract_template(name: &str) -> Option<&'static str> {
    CONTRACT_TEMPLATES.iter().copied().find(|&t| t == name)
}

/// Parse `<denom>-REV.<idx>.token` into `(denom, idx)`. Reuses the
/// Wallet-mode token-filename shape so the token subtree behaves
/// identically; the only change here is where it's rooted.
fn parse_token_filename(name: &str) -> Option<(u64, u64)> {
    const SUFFIX: &str = ".token";
    const INFIX: &str = "-REV";
    let stripped = name.strip_suffix(SUFFIX)?;
    let (lhs, idx_str) = stripped.rsplit_once('.')?;
    let denom_str = lhs.strip_suffix(INFIX)?;
    let denom: u64 = denom_str.parse().ok()?;
    let index: u64 = idx_str.parse().ok()?;
    if !f1r3drive_wallet::DENOMINATIONS.contains(&denom) {
        return None;
    }
    Some((denom, index))
}

impl Filesystem for ExtensionFs {
    fn init(&self) {
        tracing::info!(
            pubkey = %self.identity.pubkey_hex(),
            tracked = self.tracked.len(),
            "ExtensionFs mounted",
        );
    }

    fn getattr(&self, path: &Path) -> FtFsResult<FtFileAttr> {
        trace!(?path, "getattr");
        match ExtPath::parse(path, self) {
            Some(ExtPath::Root)
            | Some(ExtPath::OwnFolder)
            | Some(ExtPath::ForeignFolder(_))
            | Some(ExtPath::OwnTokensDir)
            | Some(ExtPath::OwnContractTemplateDir(_)) => Ok(self.attr_dir()),
            Some(ExtPath::OwnTokenFile { .. }) | Some(ExtPath::OwnFileEntry(_)) => {
                Ok(self.attr_file_empty())
            }
            None => Err(FtFsError::NotFound),
        }
    }

    fn readdir(&self, path: &Path) -> FtFsResult<Vec<FtDirEntry>> {
        trace!(?path, "readdir");
        match ExtPath::parse(path, self) {
            Some(ExtPath::Root) => {
                // Daemon's own pubkey folder + every tracked foreign
                // folder. Sorted so the ordering is reproducible.
                let mut entries: Vec<FtDirEntry> = Vec::new();
                entries.push(FtDirEntry::new(
                    self.own_pubkey().to_string(),
                    FileKind::Directory,
                ));
                for other in &self.tracked {
                    entries.push(FtDirEntry::new(other.clone(), FileKind::Directory));
                }
                entries.sort_by(|a, b| a.name.cmp(&b.name));
                Ok(entries)
            }

            Some(ExtPath::OwnFolder) => {
                // The three fixed children:
                //   .tokens/
                //   Paid transfer/        (and any other contract templates)
                //
                // Content files land here in slice 4+ once encrypted
                // storage is wired.
                let mut entries: Vec<FtDirEntry> = Vec::new();
                entries.push(FtDirEntry::new(TOKENS_DIR, FileKind::Directory));
                for template in CONTRACT_TEMPLATES {
                    entries.push(FtDirEntry::new(*template, FileKind::Directory));
                }
                Ok(entries)
            }

            Some(ExtPath::ForeignFolder(_)) => {
                // ADR-0002 §Decisions decision 2: readdir on foreign
                // folders returns empty. The daemon enforces this
                // even though the on-chain ciphertext names are
                // visible to any gRPC consumer.
                Ok(Vec::new())
            }

            Some(ExtPath::OwnTokensDir) => {
                // Slice 4+ wires balance → bills enumeration via
                // `BalanceCache`. For slice 3 we return empty so
                // readdir doesn't error.
                Ok(Vec::new())
            }

            Some(ExtPath::OwnContractTemplateDir(_)) => {
                // Factory folder — empty readdir. Drag a `<N>REV-*`
                // file in to list it; the resulting listing-folder
                // appears at root (slice 7).
                Ok(Vec::new())
            }

            Some(ExtPath::OwnTokenFile { .. }) | Some(ExtPath::OwnFileEntry(_)) => {
                Err(FtFsError::NotADirectory)
            }

            None => Err(FtFsError::NotFound),
        }
    }

    fn read(&self, path: &Path, _offset: u64, _size: usize, _fh: u64) -> FtFsResult<Vec<u8>> {
        // Slice 4 wires encrypted content reads. Until then: NotFound
        // for anything that didn't resolve, EACCES for foreign-folder
        // probes (consistent with "we lied in readdir").
        match ExtPath::parse(path, self) {
            Some(ExtPath::OwnFileEntry(_)) | Some(ExtPath::OwnTokenFile { .. }) => Ok(Vec::new()),
            _ => Err(FtFsError::NotFound),
        }
    }

    fn open(&self, path: &Path, _flags: i32) -> FtFsResult<u64> {
        match ExtPath::parse(path, self) {
            Some(ExtPath::OwnFileEntry(_)) | Some(ExtPath::OwnTokenFile { .. }) => Ok(0),
            _ => Err(FtFsError::NotFound),
        }
    }

    // Everything else is explicitly denied in this slice. Slice 4
    // adds create/write; slices 5-7 add delete/rename/transfer.
    fn write(&self, _path: &Path, _offset: u64, _data: &[u8], _fh: u64) -> FtFsResult<usize> {
        Err(FtFsError::PermissionDenied)
    }
    fn truncate(&self, _path: &Path, _size: u64) -> FtFsResult<()> {
        Err(FtFsError::PermissionDenied)
    }
    fn chmod(&self, _path: &Path, _mode: u32) -> FtFsResult<()> {
        Err(FtFsError::PermissionDenied)
    }
    fn create(&self, _path: &Path, _mode: u32, _flags: i32) -> FtFsResult<u64> {
        Err(FtFsError::PermissionDenied)
    }
    fn mkdir(&self, _path: &Path, _mode: u32) -> FtFsResult<()> {
        // ADR-0002: mkdir at root is restricted to pubkey folders
        // (auto-provisioned at startup) and uuid listings (minted
        // by the Paid-transfer factory in slice 7). We never accept
        // user-initiated mkdir, period.
        Err(FtFsError::PermissionDenied)
    }
    fn unlink(&self, _path: &Path) -> FtFsResult<()> {
        Err(FtFsError::PermissionDenied)
    }
    fn rmdir(&self, _path: &Path) -> FtFsResult<()> {
        Err(FtFsError::PermissionDenied)
    }
    fn rename(&self, _from: &Path, _to: &Path) -> FtFsResult<()> {
        Err(FtFsError::PermissionDenied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fs(tracked: Vec<String>) -> ExtensionFs {
        let tmp = tempfile::tempdir().unwrap();
        let identity = Arc::new(Identity::load_or_create(tmp.path()).unwrap());
        let fs = ExtensionFs::new(identity, tracked, ExtensionFsConfig::default());
        // Leak the tempdir so the identity file stays alive for the
        // life of the fs. In production this is $HOME-rooted and
        // naturally outlives the fs. The leak is bounded to one dir
        // per test; the test runner cleans $TMPDIR on exit.
        std::mem::forget(tmp);
        fs
    }

    #[test]
    fn is_pubkey_hex_requires_130_lowercase_hex_starting_04() {
        let mut valid = "04".to_string();
        valid.push_str(&"ab".repeat(64));
        assert!(is_pubkey_hex(&valid));
        // Too short.
        assert!(!is_pubkey_hex(&valid[..129]));
        // Wrong leading byte.
        let mut wrong_prefix = "03".to_string();
        wrong_prefix.push_str(&"ab".repeat(64));
        assert!(!is_pubkey_hex(&wrong_prefix));
        // Non-hex char at the end.
        let mut non_hex = "04".to_string();
        non_hex.push_str(&"ab".repeat(63));
        non_hex.push_str("ag"); // 'g' is not a hex digit
        assert_eq!(non_hex.len(), 130);
        assert!(!is_pubkey_hex(&non_hex));
    }

    #[test]
    fn parse_root() {
        let fs = make_fs(vec![]);
        assert_eq!(ExtPath::parse(Path::new("/"), &fs), Some(ExtPath::Root));
    }

    #[test]
    fn parse_own_folder() {
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        assert_eq!(
            ExtPath::parse(Path::new(&format!("/{own}")), &fs),
            Some(ExtPath::OwnFolder),
        );
    }

    #[test]
    fn parse_foreign_folder_only_when_tracked() {
        // 130-char hex that's not our pubkey.
        let foreign = format!("04{}", "ab".repeat(64));
        let untracked = make_fs(vec![]);
        assert_eq!(
            ExtPath::parse(Path::new(&format!("/{foreign}")), &untracked),
            None,
        );
        let tracked = make_fs(vec![foreign.clone()]);
        assert_eq!(
            ExtPath::parse(Path::new(&format!("/{foreign}")), &tracked),
            Some(ExtPath::ForeignFolder(foreign.clone())),
        );
    }

    #[test]
    fn parse_tokens_subtree() {
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        assert_eq!(
            ExtPath::parse(Path::new(&format!("/{own}/.tokens")), &fs),
            Some(ExtPath::OwnTokensDir),
        );
        assert_eq!(
            ExtPath::parse(Path::new(&format!("/{own}/.tokens/100-REV.0.token")), &fs),
            Some(ExtPath::OwnTokenFile {
                denom: 100,
                index: 0,
            }),
        );
    }

    #[test]
    fn parse_contract_template_subfolder() {
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        assert_eq!(
            ExtPath::parse(Path::new(&format!("/{own}/Paid transfer")), &fs),
            Some(ExtPath::OwnContractTemplateDir("Paid transfer")),
        );
    }

    #[test]
    fn parse_arbitrary_filename_in_own_folder() {
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        assert_eq!(
            ExtPath::parse(Path::new(&format!("/{own}/notes.txt")), &fs),
            Some(ExtPath::OwnFileEntry("notes.txt".into())),
        );
    }

    #[test]
    fn parse_foreign_file_path_is_none() {
        // Even if the foreign pubkey is tracked, a nested file path
        // under it returns None — we lie uniformly about foreign
        // folder contents.
        let foreign = format!("04{}", "ab".repeat(64));
        let fs = make_fs(vec![foreign.clone()]);
        assert_eq!(
            ExtPath::parse(Path::new(&format!("/{foreign}/some-file")), &fs),
            None,
        );
    }

    #[test]
    fn root_readdir_lists_own_plus_tracked() {
        let foreign = format!("04{}", "ab".repeat(64));
        let fs = make_fs(vec![foreign.clone()]);
        let entries = fs.readdir(Path::new("/")).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&fs.own_pubkey()));
        assert!(names.contains(&foreign.as_str()));
    }

    #[test]
    fn own_folder_readdir_has_tokens_and_paid_transfer() {
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        let entries = fs.readdir(Path::new(&format!("/{own}"))).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&TOKENS_DIR));
        assert!(names.contains(&PAID_TRANSFER_DIR));
    }

    #[test]
    fn foreign_folder_readdir_is_empty() {
        let foreign = format!("04{}", "ab".repeat(64));
        let fs = make_fs(vec![foreign.clone()]);
        let entries = fs.readdir(Path::new(&format!("/{foreign}"))).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn unknown_pubkey_folder_is_not_found() {
        let fs = make_fs(vec![]);
        let foreign = format!("04{}", "ab".repeat(64));
        assert!(matches!(
            fs.getattr(Path::new(&format!("/{foreign}"))),
            Err(FtFsError::NotFound)
        ));
    }

    #[test]
    fn mkdir_is_always_rejected() {
        let fs = make_fs(vec![]);
        assert!(matches!(
            fs.mkdir(Path::new("/anything"), 0o755),
            Err(FtFsError::PermissionDenied),
        ));
        let own = fs.own_pubkey().to_string();
        assert!(matches!(
            fs.mkdir(Path::new(&format!("/{own}/newfolder")), 0o755),
            Err(FtFsError::PermissionDenied),
        ));
    }

    #[test]
    fn write_create_delete_rename_all_denied_in_this_slice() {
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        let p = format!("/{own}/newfile");
        assert!(matches!(
            fs.create(Path::new(&p), 0o644, 0),
            Err(FtFsError::PermissionDenied),
        ));
        assert!(matches!(
            fs.write(Path::new(&p), 0, b"x", 0),
            Err(FtFsError::PermissionDenied),
        ));
        assert!(matches!(
            fs.unlink(Path::new(&p)),
            Err(FtFsError::PermissionDenied),
        ));
        assert!(matches!(
            fs.rename(Path::new(&p), Path::new("/other")),
            Err(FtFsError::PermissionDenied),
        ));
    }

    #[test]
    fn tracked_list_dedupes_and_drops_self() {
        let tmp = tempfile::tempdir().unwrap();
        let identity = Arc::new(Identity::load_or_create(tmp.path()).unwrap());
        let own = identity.pubkey_hex().to_string();
        let other = format!("04{}", "cd".repeat(64));
        let fs = ExtensionFs::new(
            Arc::clone(&identity),
            vec![
                own.clone(),          // dropped: that's us
                other.clone(),        //
                other.clone(),        // dedup
                other.to_uppercase(), // case-fold dedup
            ],
            ExtensionFsConfig::default(),
        );
        assert_eq!(fs.tracked, vec![other]);
    }
}
