//! `ExtensionFs` — the `--mount-mode=extension` filesystem.
//!
//! Per-user folders named by uncompressed secp256k1 pubkey hex (130
//! chars). Non-owners see other users' folders exist but
//! `readdir` on them returns empty — the ACL is daemon-enforced, not
//! chain-enforced. See `docs/architecture/ADR-0002-extension-design.md`.
//!
//! Slices 3–13: path parsing + ACL + readdir + encrypted
//! create/read/write/release through the SELF envelope + unlink +
//! rename (same-folder SELF rename and cross-folder SELF→RECV
//! re-wrap for peer transfers) + contract-folder plug-ins (drops
//! into `/<me>/<template>/<N>REV-rest` encrypt + persist the file
//! on-chain under a fresh `K_listing`, mint a uuid-listing at root,
//! and let the owner `rmdir` to retire it) + disk-backed
//! `ListingStore` + cross-daemon listing discovery via an on-chain
//! manifest + listing introspection through a synthetic
//! `/<uuid>/.info` JSON file (so prospective buyers can inspect
//! price / filename / owner before dropping a token). The actual
//! on-chain Rholang factory + REV routing stays future work; the
//! token-drop rename path currently short-circuits with
//! `NotSupported`. Edit-existing-file semantics replace the prior
//! blob instead of accumulating duplicates (slice 12), covering
//! both own SELF edits and recipient edits of a RECV blob. Rename
//! accepts RECV sources (slice 13): within-folder promotes
//! RECV→SELF (ownership transfer), cross-folder re-wraps RECV→RECV
//! for a new recipient (forwarding).
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

use std::collections::HashMap;
use std::path::{Component, Path};
use std::sync::{atomic::AtomicU64, Arc, Mutex, RwLock};
use std::time::SystemTime;

use libfuse_t_rs::{
    DirEntry as FtDirEntry, FileAttr as FtFileAttr, FileKind, Filesystem, FsError as FtFsError,
    FsResult as FtFsResult,
};
use tracing::{trace, warn};

use f1r3drive_crypto::{
    envelope::{self, UnwrappedBlob},
    generate_key, key_fingerprint, Keystore, SymKey,
};
use f1r3drive_identity::Identity;

use crate::blob_store::{BlobError, BlobStore};
use crate::contract_template::{is_listing_id, mint_listing_id, ContractRegistry};
use crate::factory_client::FactoryClient;
use crate::listing_store::{Listing, ListingStore};

/// Length of a pubkey-folder name in hex characters.
///
/// 65-byte uncompressed secp256k1 pubkey (`0x04 || x || y`) encoded
/// as 2 hex chars per byte = 130 chars. The folder name is always
/// lowercase; the parser accepts mixed-case for robustness and
/// normalises internally.
pub const PUBKEY_HEX_LEN: usize = 130;

/// Name of the per-wallet token subtree (unchanged from ADR-0001).
pub const TOKENS_DIR: &str = ".tokens";

/// Name of the fixed Paid-transfer factory folder. Kept as a
/// top-level public constant so existing callers (and the parse-time
/// shape checks) don't have to go through the registry for the
/// common case. The registry itself holds the canonical list.
pub const PAID_TRANSFER_DIR: &str = "Paid transfer";

/// Reserved BlobStore channel name holding a JSON manifest of the
/// owner's active listings. Tracked peers read it on `readdir /` to
/// surface each other's listings without a shared `ListingStore`.
/// The underscore prefix keeps it from colliding with 32-char hex
/// listing ids or lower-case hex SELF/RECV channels.
pub const LISTINGS_MANIFEST_CHANNEL: &str = "_manifest";

/// Virtual filename exposed inside every listing-uuid folder. Serving
/// this read-only lets a prospective buyer inspect price, template,
/// and plaintext filename before dropping a token on the listing.
pub const LISTING_INFO_FILE: &str = ".info";

/// Tunables for attribute display + ACL interaction.
#[derive(Debug, Clone)]
pub struct ExtensionFsConfig {
    pub display_uid: u32,
    pub display_gid: u32,
}

impl Default for ExtensionFsConfig {
    fn default() -> Self {
        // Report the mounting user's uid/gid in getattr so the kernel's
        // VFS perm-check accepts writes. Returning 0 (the derived
        // Default) made every entry root-owned, which the macOS NFSv4
        // client rejected before any FUSE call could land — Finder
        // surfaced this as a bogus "name "" already exists" dialog.
        Self {
            display_uid: unsafe { libc::getuid() },
            display_gid: unsafe { libc::getgid() },
        }
    }
}

/// FUSE-side implementation of ADR-0002's extension mount.
pub struct ExtensionFs {
    identity: Arc<Identity>,
    /// Foreign pubkey folders to render in `readdir /`. Lowercase hex
    /// (130 chars each); the daemon never serves readdir CONTENT for
    /// these — only their existence.
    tracked: Vec<String>,
    config: ExtensionFsConfig,
    blobs: Arc<dyn BlobStore>,
    keystore: Arc<Keystore>,
    /// Contract-folder registry. Fixed set of templates whose
    /// subfolder names are reserved under every owner's folder.
    registry: Arc<ContractRegistry>,
    /// Minted listings. Each listing surfaces as a uuid-folder under
    /// the mount root until it's `rmdir`'d by the owner (slice 8+).
    listings: Arc<ListingStore>,
    /// On-chain factory client. When `Some`, drop-into-Paid-transfer
    /// routes through `paid_transfer_mint`, `rmdir /<listing>/`
    /// routes through `paid_transfer_rmdir`, and token-drop renames
    /// into a uuid-listing route through `paid_transfer_purchase`.
    /// When `None`, mint stores the SELF envelope locally under the
    /// owner's prefix (slice-8 behavior) and rmdir is purely local.
    factory: Option<Arc<FactoryClient>>,
    /// Owner's REV address, cached so the mint path doesn't have to
    /// re-derive it per drop. `None` when the daemon doesn't have a
    /// factory client (= no on-chain path needed).
    owner_rev: Option<String>,
    /// Per-fd write-side state. FUSE delivers writes in chunks; we
    /// buffer in memory until flush/release and then encrypt the whole
    /// payload as one SELF blob. Keyed by (plaintext-filename). We
    /// drop the entry on release.
    pending_writes: Arc<RwLock<HashMap<String, Mutex<PendingWrite>>>>,
    next_fh: AtomicU64,
    /// Read-side cache. On open-for-read we fetch + decrypt the full
    /// envelope once; subsequent `read(offset, size)` calls slice the
    /// cached plaintext. Keyed by filename. Dropped on release.
    read_cache: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    /// Plaintext-size memo keyed by own-folder filename. `getattr`
    /// consults this before falling back to fetching + decrypting
    /// the envelope — macOS/fuse-t polls getattr dozens of times per
    /// second per entry during readdir, and a chain + decrypt round
    /// trip there would stall writes behind the pile-up (both ops
    /// serialize on the shared `NodeClient` mutex). Populated by
    /// `open` / `write` / `release` / the slow `getattr` miss path;
    /// cleared on `unlink`.
    size_cache: Arc<RwLock<HashMap<String, u64>>>,
    /// Wall-clock memo keyed by own-folder filename. We don't
    /// persist timestamps on the blob yet (that's a v0.2 envelope
    /// schema change), so this is best-effort within a daemon's
    /// lifetime. Finder renders fresh writes with real timestamps
    /// instead of 1969-12-31. Cleared on `unlink`.
    times_cache: Arc<RwLock<HashMap<String, TimeTriple>>>,
}

/// `(atime, mtime, ctime)` captured on create/open/write/release
/// for an own-folder file. Lifted out of the `ExtensionFs` field so
/// the struct's type is readable at a glance.
type TimeTriple = (SystemTime, SystemTime, SystemTime);

/// Buffered-write state attached to one open-for-write file.
#[derive(Debug)]
struct PendingWrite {
    bytes: Vec<u8>,
    cipher_channel: Option<String>, // from `create` if this is a new file
}

impl ExtensionFs {
    pub fn new(
        identity: Arc<Identity>,
        tracked_pubkeys: Vec<String>,
        config: ExtensionFsConfig,
        blobs: Arc<dyn BlobStore>,
        keystore: Arc<Keystore>,
    ) -> Self {
        Self::with_registry(
            identity,
            tracked_pubkeys,
            config,
            blobs,
            keystore,
            Arc::new(ContractRegistry::new()),
            Arc::new(ListingStore::new()),
        )
    }

    /// Attach an on-chain factory client. When present, mint / rmdir /
    /// token-drop renames route through the Rholang factory instead
    /// of staying local.
    pub fn with_factory(mut self, factory: Arc<FactoryClient>, owner_rev: String) -> Self {
        self.factory = Some(factory);
        self.owner_rev = Some(owner_rev);
        self
    }

    /// Full constructor exposing the contract-folder registry and
    /// listing store for tests + callers that want to inject custom
    /// template plug-ins.
    pub fn with_registry(
        identity: Arc<Identity>,
        tracked_pubkeys: Vec<String>,
        config: ExtensionFsConfig,
        blobs: Arc<dyn BlobStore>,
        keystore: Arc<Keystore>,
        registry: Arc<ContractRegistry>,
        listings: Arc<ListingStore>,
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
            blobs,
            keystore,
            registry,
            listings,
            factory: None,
            owner_rev: None,
            pending_writes: Arc::new(RwLock::new(HashMap::new())),
            next_fh: AtomicU64::new(1),
            read_cache: Arc::new(RwLock::new(HashMap::new())),
            size_cache: Arc::new(RwLock::new(HashMap::new())),
            times_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn own_pubkey(&self) -> &str {
        self.identity.pubkey_hex()
    }

    /// Fetch every blob stored under the owner's prefix, decrypt
    /// each one, and return `(plaintext_filename, cipher_channel)`
    /// pairs. Handles both SELF blobs (owner-wrote-to-self) and RECV
    /// blobs (someone else wrapped a transfer for us). Blobs the
    /// daemon can't decrypt are skipped with a warning. Listing
    /// blobs (whose channel == a known listing id) and the
    /// `_manifest` channel are excluded — those surface at root as
    /// `/<listing-uuid>/` folders, not as regular files inside the
    /// owner's folder.
    fn list_own_entries(&self) -> FtFsResult<Vec<(String, String)>> {
        let channels = self.blobs.list(self.own_pubkey()).map_err(blob_to_errno)?;
        let listing_channels: std::collections::HashSet<String> =
            self.listings.ids().into_iter().collect();
        let mut out = Vec::with_capacity(channels.len());
        for ch in channels {
            if ch == LISTINGS_MANIFEST_CHANNEL || listing_channels.contains(&ch) {
                continue;
            }
            let blob = match self.blobs.get(self.own_pubkey(), &ch) {
                Ok(Some(b)) => b,
                Ok(None) => continue,
                Err(e) => {
                    warn!(err = ?e, "blob get failed for {ch}; skipping");
                    continue;
                }
            };
            match self.try_decrypt(&blob) {
                Ok(unw) => out.push((unw.filename, ch)),
                Err(e) => {
                    warn!(err = ?e, "envelope unwrap failed for {ch}; skipping");
                }
            }
        }
        Ok(out)
    }

    /// Serialize the owner's current `ListingStore` and publish it
    /// to BlobStore at `(own_prefix, LISTINGS_MANIFEST_CHANNEL)`.
    /// Tracked peers fetch this to surface our listings in their
    /// readdir. Errors are logged + swallowed: the local store is
    /// still correct, the manifest just lagged.
    fn publish_own_manifest(&self) {
        let snapshot: HashMap<String, Listing> = self
            .listings
            .ids()
            .into_iter()
            .filter_map(|id| self.listings.get(&id).map(|l| (id, l)))
            .collect();
        let bytes = match serde_json::to_vec(&snapshot) {
            Ok(b) => b,
            Err(e) => {
                warn!(err = ?e, "manifest encode failed; skipping publish");
                return;
            }
        };
        if let Err(e) = self
            .blobs
            .put(self.own_pubkey(), LISTINGS_MANIFEST_CHANNEL, &bytes)
        {
            warn!(err = ?e, "manifest publish failed; peers may not see our listings");
        }
    }

    /// Resolve a listing by id from either the local store or (for
    /// cross-daemon introspection) any tracked peer's on-chain
    /// manifest. Returned Listing carries owner_pubkey so the caller
    /// doesn't need to know where the hit came from.
    fn resolve_listing(&self, listing_id: &str) -> Option<Listing> {
        if let Some(l) = self.listings.get(listing_id) {
            return Some(l);
        }
        for prefix in &self.tracked {
            if let Some(l) = self.fetch_peer_manifest(prefix).get(listing_id).cloned() {
                return Some(l);
            }
        }
        None
    }

    /// Serialize a listing's public metadata as pretty JSON. Served
    /// at `/<id>/.info`. The owner pubkey lives inside the JSON
    /// alongside spec + template name — tools inspecting a listing
    /// don't need to know the on-chain prefix layout.
    fn listing_info_bytes(&self, listing_id: &str) -> FtFsResult<Vec<u8>> {
        let listing = self
            .resolve_listing(listing_id)
            .ok_or(FtFsError::NotFound)?;
        serde_json::to_vec_pretty(&listing).map_err(|e| {
            warn!(err = ?e, listing_id, "listing info encode failed");
            FtFsError::Io
        })
    }

    /// True iff any tracked peer's manifest claims `listing_id`.
    /// Used by `ExtPath::parse` to resolve `/<peer-listing>` paths
    /// so Bob's `getattr`/`readdir` on Alice's listing works, not
    /// just the top-level root readdir.
    fn peer_knows_listing(&self, listing_id: &str) -> bool {
        self.tracked
            .iter()
            .any(|p| self.fetch_peer_manifest(p).contains_key(listing_id))
    }

    /// Fetch + decode a peer's manifest. Returns an empty map if
    /// the peer hasn't published one yet, if the blob fetch fails,
    /// or if the JSON is malformed — in all three cases we'd rather
    /// hide listings than fail the whole `readdir /`.
    fn fetch_peer_manifest(&self, prefix: &str) -> HashMap<String, Listing> {
        match self.blobs.get(prefix, LISTINGS_MANIFEST_CHANNEL) {
            Ok(Some(bytes)) => match serde_json::from_slice::<HashMap<String, Listing>>(&bytes) {
                Ok(m) => m,
                Err(e) => {
                    warn!(err = ?e, prefix, "peer manifest decode failed; treating as empty");
                    HashMap::new()
                }
            },
            Ok(None) => HashMap::new(),
            Err(e) => {
                warn!(err = ?e, prefix, "peer manifest fetch failed; treating as empty");
                HashMap::new()
            }
        }
    }

    /// Decrypt a stored envelope. Dispatches on the 4-byte tag:
    /// `SELF` uses the daemon's keystore (symmetric K indexed by its
    /// Blake2b fingerprint); `RECV` uses the identity's private key
    /// to ECIES-unwrap the fresh K minted by the sender.
    fn try_decrypt(&self, blob: &[u8]) -> FtFsResult<UnwrappedBlob> {
        if blob.len() < 4 {
            return Err(FtFsError::Io);
        }
        match &blob[..4] {
            b"SELF" => self.decrypt_self(blob),
            b"RECV" => self.decrypt_recv(blob),
            _ => Err(FtFsError::Io),
        }
    }

    /// Pull a key out of the keystore + unwrap a SELF envelope.
    fn decrypt_self(&self, blob: &[u8]) -> FtFsResult<UnwrappedBlob> {
        // Blob = "SELF" || blake2b256(K) || sealed. Pull the
        // fingerprint before calling envelope::unwrap_self so we can
        // tell the caller which key we needed if load fails.
        if blob.len() < 4 + 32 {
            return Err(FtFsError::Io);
        }
        let mut fp = [0u8; 32];
        fp.copy_from_slice(&blob[4..36]);
        let key = self
            .keystore
            .load(&fp)
            .map_err(|_| FtFsError::Io)?
            .ok_or(FtFsError::Io)?;
        envelope::unwrap_self(&key, blob).map_err(|_| FtFsError::Io)
    }

    /// Unwrap a RECV envelope using our identity's private key.
    fn decrypt_recv(&self, blob: &[u8]) -> FtFsResult<UnwrappedBlob> {
        let priv_bytes = self.identity.private_key_bytes();
        envelope::unwrap_recv(&priv_bytes, blob).map_err(|_| FtFsError::Io)
    }

    /// Peel the SELF tag + fingerprint off a blob and resolve the
    /// symmetric key through the keystore. Used by rename-within-own
    /// to preserve K across the re-wrap (filename changes, K stays).
    fn self_key_for(&self, blob: &[u8]) -> FtFsResult<SymKey> {
        if blob.len() < 4 + 32 || &blob[..4] != b"SELF" {
            return Err(FtFsError::Io);
        }
        let mut fp = [0u8; 32];
        fp.copy_from_slice(&blob[4..36]);
        self.keystore
            .load(&fp)
            .map_err(|_| FtFsError::Io)?
            .ok_or(FtFsError::Io)
    }

    /// Look up the cipher channel currently storing `filename` in
    /// the owner's folder.
    fn find_own_channel(&self, filename: &str) -> FtFsResult<String> {
        self.list_own_entries()?
            .into_iter()
            .find(|(n, _)| n == filename)
            .map(|(_, c)| c)
            .ok_or(FtFsError::NotFound)
    }

    /// Called when a contract-template drop closes (release). Two
    /// paths depending on whether a `FactoryClient` is attached:
    ///
    /// - **With factory** (`--chain-factory`): encrypt the plaintext
    ///   under a fresh `K_listing`, deploy `paid_transfer_mint`, pull
    ///   the factory URI back, record a `Listing` with
    ///   `listing_uri = Some(uri)`. No BlobStore involvement — the
    ///   factory holds the ciphertext + K on-chain.
    /// - **Without factory** (local): same as slice 8 — encrypt +
    ///   store as a SELF envelope under the owner's prefix with
    ///   channel == listing id; record a `Listing` with
    ///   `listing_uri = None`.
    ///
    /// Both paths parse the dropped filename via the template, mint
    /// `K_listing` locally, and publish the owner's manifest after.
    fn mint_listing_from_drop(
        &self,
        template: &'static str,
        name: &str,
        bytes: &[u8],
    ) -> FtFsResult<()> {
        let template_impl = self.registry.find(template).ok_or(FtFsError::NotFound)?;
        let spec = template_impl
            .parse(name)
            .ok_or(FtFsError::InvalidArgument)?;
        let (price, plaintext_filename) = match &spec {
            crate::contract_template::ListingSpec::PaidTransfer { price, filename } => {
                (*price, filename.clone())
            }
        };

        // Mint K_listing + store in the local keystore. The owner's
        // daemon holds this key regardless of path; the on-chain
        // factory stores a copy too but the local one is what
        // decrypts the eventual RECV blob when the owner views
        // their own listings post-purchase.
        let k = generate_key();
        self.keystore.store(&k).map_err(|_| FtFsError::Io)?;
        let (listing_envelope, _fp) =
            envelope::wrap_self(&k, &plaintext_filename, bytes).map_err(|_| FtFsError::Io)?;

        let (id, listing_uri, escrow_address) =
            match (self.factory.as_ref(), self.owner_rev.as_deref()) {
                (Some(factory), Some(owner_rev)) => {
                    // On-chain path.
                    let minted = factory
                        .mint_listing(owner_rev, price, &listing_envelope.bytes, k.as_bytes())
                        .map_err(|e| {
                            warn!(err = ?e, "factory mint deploy failed");
                            FtFsError::Io
                        })?;
                    let id = mint_listing_id();
                    (id, Some(minted.listing_uri), Some(minted.escrow_address))
                }
                _ => {
                    // Local path (slice-8 behavior).
                    let id = mint_listing_id();
                    self.blobs
                        .put(self.own_pubkey(), &id, &listing_envelope.bytes)
                        .map_err(blob_to_errno)?;
                    (id, None, None)
                }
            };

        let listing = Listing {
            owner_pubkey_hex: self.own_pubkey().to_string(),
            template_name: template_impl.name().to_string(),
            spec,
            listing_uri: listing_uri.clone(),
            escrow_address: escrow_address.clone(),
        };
        tracing::info!(
            listing_id = %id,
            template = template_impl.name(),
            payload_bytes = bytes.len(),
            on_chain = listing_uri.is_some(),
            "minted listing from contract-template drop"
        );
        self.listings.insert(id, listing);
        self.publish_own_manifest();
        Ok(())
    }

    /// Handle a token-drop rename as a paid-transfer purchase.
    /// Needs the daemon to have an attached `FactoryClient` + the
    /// listing to have an on-chain URI; without either, the drop
    /// returns `NotSupported` with a clear tracing message.
    ///
    /// On success: the factory ran the REV transfer buyer→owner,
    /// released `(encryptedBlob, kListing)` on the reply channel,
    /// and we store a fresh RECV blob under the buyer's prefix so
    /// the file appears in Finder on the buyer's next readdir.
    fn purchase_via_factory(&self, from: &Path, to: &Path) -> FtFsResult<()> {
        let factory = match self.factory.as_ref() {
            Some(f) => f,
            None => {
                tracing::info!(
                    ?from,
                    ?to,
                    "token drop with no factory client attached — need --chain-factory"
                );
                return Err(FtFsError::NotSupported);
            }
        };
        let buyer_rev = self.owner_rev.as_deref().ok_or_else(|| {
            tracing::warn!("factory attached but owner_rev missing — construction bug");
            FtFsError::Io
        })?;

        // Destination: `/<listing-uuid>/<anything>`.
        let listing_id = extract_listing_id_from_dest(to).ok_or(FtFsError::InvalidArgument)?;
        // Resolve first against the local store (we own the listing)
        // and fall back to the cross-daemon peer manifests (we're the
        // buyer, the seller's daemon published the URI). The
        // readdir-at-root path already consults both — purchase
        // needs the same fallback or buyers can see a listing they
        // can't actually act on.
        let listing = self.listings.get(&listing_id).or_else(|| {
            self.tracked
                .iter()
                .find_map(|p| self.fetch_peer_manifest(p).get(&listing_id).cloned())
        });
        let listing = listing.ok_or(FtFsError::NotFound)?;
        let listing_uri = listing.listing_uri.as_deref().ok_or_else(|| {
            tracing::info!(
                %listing_id,
                "token drop on a local-only listing; buyer flow needs on-chain URI"
            );
            FtFsError::NotSupported
        })?;
        let escrow_address = listing.escrow_address.as_deref().ok_or_else(|| {
            // Should always be Some for on-chain-minted listings
            // post-factory-redesign. A None here means the seller
            // minted on a daemon that pre-dated the escrow + release
            // flow and the URI alone can't drive purchase.
            tracing::warn!(
                %listing_id,
                "listing has URI but no escrow address — minted before the escrow redesign"
            );
            FtFsError::NotSupported
        })?;
        let price = match &listing.spec {
            crate::contract_template::ListingSpec::PaidTransfer { price, .. } => *price,
        };

        tracing::info!(
            buyer = %self.own_pubkey(),
            seller = %listing.owner_pubkey_hex,
            %listing_id,
            price,
            "invoking factory purchase (transfer -> escrow -> release)"
        );
        let payload = factory
            .purchase_listing(listing_uri, buyer_rev, escrow_address, price)
            .map_err(|e| {
                warn!(err = ?e, "factory purchase deploy failed");
                FtFsError::Io
            })?;

        // The factory returned (encrypted_blob, k_listing). Decrypt
        // via unwrap_self and re-wrap as a RECV for ourselves so
        // the file appears under our prefix.
        let k = f1r3drive_crypto::SymKey::from_bytes(&payload.k_listing).ok_or_else(|| {
            warn!("released K_listing is not 32 bytes");
            FtFsError::Io
        })?;
        let unwrapped = envelope::unwrap_self(&k, &payload.encrypted_blob).map_err(|e| {
            warn!(err = ?e, "unwrap_self of released blob failed");
            FtFsError::Io
        })?;
        let own_pubkey_bytes = hex::decode(self.own_pubkey()).map_err(|_| FtFsError::Io)?;
        let recv_envelope =
            envelope::wrap_recv(&own_pubkey_bytes, &unwrapped.filename, &unwrapped.plaintext)
                .map_err(|_| FtFsError::Io)?;
        let channel = cipher_channel_for(&recv_envelope.bytes);
        self.blobs
            .put(self.own_pubkey(), &channel, &recv_envelope.bytes)
            .map_err(blob_to_errno)?;

        // The source token file isn't actually removed — the REV
        // movement happened on the vault side as part of the deploy.
        // The `.tokens/` subtree is a synthetic view of the vault's
        // balance; a subsequent readdir will show it rebalanced.
        tracing::info!(
            %listing_id,
            file = %unwrapped.filename,
            "purchase complete; RECV blob stored under buyer prefix"
        );
        Ok(())
    }

    /// After a successful flush, delete the blob at `old_channel`
    /// if it differs from the new channel. We swallow + log blob
    /// errors here: the new blob is already live, and leaving an
    /// orphaned old blob behind degrades gracefully (future readdir
    /// skips it on key-fingerprint mismatch, but it costs storage).
    /// Also GCs the orphaned keystore entry if no other blob
    /// references the same key.
    fn gc_replaced_blob(&self, old_channel: Option<&str>, new_channel: &str) {
        let Some(old) = old_channel else { return };
        if old == new_channel {
            return;
        }
        // Snapshot the fingerprint from the OLD blob BEFORE deleting
        // so we can clean up its keystore entry too.
        let old_fp = self.self_key_fingerprint(old);
        if let Err(e) = self.blobs.delete(self.own_pubkey(), old) {
            warn!(err = ?e, old, new = new_channel, "gc of replaced blob failed; orphan left behind");
            return;
        }
        if let Some(fp) = old_fp {
            self.gc_orphaned_key(&fp);
        }
    }

    /// Extract the Blake2b fingerprint from a SELF envelope stored
    /// at `channel`. Returns `None` if the blob is missing, isn't
    /// SELF-tagged, or too short to carry one.
    fn self_key_fingerprint(&self, channel: &str) -> Option<[u8; 32]> {
        let blob = self.blobs.get(self.own_pubkey(), channel).ok()??;
        if blob.len() < 4 + 32 || &blob[..4] != b"SELF" {
            return None;
        }
        let mut fp = [0u8; 32];
        fp.copy_from_slice(&blob[4..36]);
        Some(fp)
    }

    /// Drop the keystore entry at `fingerprint` if no remaining
    /// SELF blob under the owner's prefix references it. Best-
    /// effort — a failed check leaves the key in place (storage
    /// cost only, no correctness impact).
    ///
    /// The scan is O(N) in the number of own-prefix blobs. For the
    /// current workload (dozens of blobs per user) this is cheap;
    /// if churn grows we'd move to a ref-counted on-disk index.
    fn gc_orphaned_key(&self, fingerprint: &[u8; 32]) {
        let channels = match self.blobs.list(self.own_pubkey()) {
            Ok(c) => c,
            Err(e) => {
                warn!(err = ?e, "keystore gc: can't list blobs; skipping");
                return;
            }
        };
        for ch in channels {
            if let Some(fp) = self.self_key_fingerprint(&ch) {
                if &fp == fingerprint {
                    // Still referenced by at least one blob — keep.
                    return;
                }
            }
        }
        if let Err(e) = self.keystore.delete(fingerprint) {
            warn!(err = ?e, "keystore delete failed; orphan key left on disk");
        }
    }

    /// Encrypt + persist the pending bytes for `filename`. Called on
    /// release/flush when a write-side fd closes. Returns the
    /// channel the new blob landed under so the caller can clean up
    /// an older blob at a different channel (edit-existing path).
    fn flush_pending(&self, filename: &str, pending: &PendingWrite) -> FtFsResult<String> {
        let key = generate_key();
        let fp = self.keystore.store(&key).map_err(|_| FtFsError::Io)?;
        let (envelope, fp2) =
            envelope::wrap_self(&key, filename, &pending.bytes).map_err(|_| FtFsError::Io)?;
        debug_assert_eq!(fp, fp2);
        let channel = pending
            .cipher_channel
            .clone()
            .unwrap_or_else(|| cipher_channel_for(&envelope.bytes));
        self.blobs
            .put(self.own_pubkey(), &channel, &envelope.bytes)
            .map_err(blob_to_errno)?;
        Ok(channel)
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
            // Owner `rw-` so the kernel VFS perm-check lets the
            // mounting user open existing own-folder files for
            // write (edits + truncates). 0o444 made every file
            // look read-only to macOS and the write bounced before
            // reaching FUSE — `create` was never called.
            perm: 0o644,
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

    /// Shape an own-file attr with a known plaintext size and an
    /// optional captured `(atime, mtime, ctime)` triple from
    /// `times_cache`. Timestamps aren't persisted on the blob yet,
    /// so an unknown triple means "serve the Unix epoch" (which
    /// `attr_file_empty` provides by default).
    fn attr_file_with(&self, size: u64, times: Option<TimeTriple>) -> FtFileAttr {
        let base = self.attr_file_empty();
        match times {
            Some((atime, mtime, ctime)) => FtFileAttr {
                size,
                atime,
                mtime,
                ctime,
                ..base
            },
            None => FtFileAttr { size, ..base },
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
    /// `/<my-pubkey>/<template>/` where `<template>` is a registered
    /// contract-folder (e.g. `Paid transfer`).
    OwnContractTemplateDir(&'static str),
    /// `/<my-pubkey>/<template>/<filename>` — a file dropped into a
    /// contract-folder. `release` on this path triggers the
    /// template's parse + mint flow.
    OwnContractTemplateFile {
        template: &'static str,
        name: String,
    },
    /// `/<my-pubkey>/<file>` where `<file>` isn't a known subfolder —
    /// a user content file (slice 4+ decrypts and reads).
    OwnFileEntry(String),
    /// `/<listing-uuid>/` — a minted listing. Owner is recorded in
    /// the `ListingStore`.
    UuidListing(String),
    /// `/<listing-uuid>/.info` — a synthetic read-only JSON view of
    /// a listing's public metadata (owner, template, price,
    /// plaintext filename). Lets a prospective buyer inspect a
    /// listing before committing to a token drop.
    UuidListingInfo(String),
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
                // 32-char hex → listing. 130-char hex starting 04 → pubkey.
                // Length-disjointedness means we don't need a tag byte.
                if is_listing_id(first) {
                    // Resolve against the local ListingStore first,
                    // then (for cross-daemon discovery) against each
                    // tracked peer's on-chain manifest.
                    if fs.listings.get(first).is_some() || fs.peer_knows_listing(first) {
                        return Some(Self::UuidListing((*first).to_string()));
                    }
                    return None;
                }
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
                // Listing introspection: `/<uuid>/.info` is the one
                // nested path shape a uuid folder exposes.
                if is_listing_id(first)
                    && *second == LISTING_INFO_FILE
                    && (fs.listings.get(first).is_some() || fs.peer_knows_listing(first))
                {
                    return Some(Self::UuidListingInfo((*first).to_string()));
                }
                let folder = first.to_lowercase();
                if !is_pubkey_hex(&folder) || !fs.is_own(&folder) {
                    // Only the owner's own folder has subshapes
                    // visible to the daemon.
                    return None;
                }
                match *second {
                    TOKENS_DIR => Some(Self::OwnTokensDir),
                    name => match fs.registry.find(name) {
                        Some(template) => Some(Self::OwnContractTemplateDir(template.name())),
                        None => Some(Self::OwnFileEntry(name.to_string())),
                    },
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

            [first, template, filename] => {
                // A file dropped INTO a contract-template subfolder.
                // The template must be registered; otherwise this
                // slot doesn't exist as a directory in the first
                // place.
                let folder = first.to_lowercase();
                if !is_pubkey_hex(&folder) || !fs.is_own(&folder) {
                    return None;
                }
                let registered = fs.registry.find(template)?;
                Some(Self::OwnContractTemplateFile {
                    template: registered.name(),
                    name: (*filename).to_string(),
                })
            }

            _ => None,
        }
    }
}

/// Derive the on-chain channel name for a freshly-written envelope.
/// We use blake2b256(envelope_bytes) truncated to 16 bytes of hex so
/// (a) the name is stable per blob, (b) collisions are
/// astronomically rare for distinct ciphertexts.
fn cipher_channel_for(envelope_bytes: &[u8]) -> String {
    let fp = key_fingerprint(envelope_bytes);
    hex::encode(&fp[..16])
}

/// Key used in `pending_writes` for a contract-template drop. The
/// composite shape `<template>/<name>` keeps template drops from
/// colliding with regular file writes keyed by plain `<name>`.
fn template_pending_key(template: &str, name: &str) -> String {
    format!("{template}/{name}")
}

/// Recognise the ADR-0002 purchase shape — a rename whose source
/// is a token file in the daemon's own `.tokens/` subtree and whose
/// destination is a filename inside a known listing uuid folder.
/// The slice-11 daemon doesn't execute the purchase; it only
/// returns a clear error pointing at the pending factory work.
/// Extract the first component of `path` if it's a listing uuid.
/// Used by the purchase-via-factory path to find the destination
/// listing's id from a `/<uuid>/<anything>` rename.
fn extract_listing_id_from_dest(path: &Path) -> Option<String> {
    let mut comps = path.components();
    if comps.next() != Some(Component::RootDir) {
        return None;
    }
    let first = match comps.next()? {
        Component::Normal(s) => s.to_str()?,
        _ => return None,
    };
    if !is_listing_id(first) {
        return None;
    }
    Some(first.to_string())
}

fn looks_like_token_drop_onto_listing(from: &Path, to: &Path, fs: &ExtensionFs) -> bool {
    let Some(ExtPath::OwnTokenFile { .. }) = ExtPath::parse(from, fs) else {
        return false;
    };
    // Destination: `/<listing-uuid>/<anything>` where the uuid is
    // known locally or via a tracked peer's manifest.
    let mut comps = to.components();
    if comps.next() != Some(Component::RootDir) {
        return false;
    }
    let first = match comps.next() {
        Some(Component::Normal(s)) => s.to_str(),
        _ => return false,
    };
    let has_second = matches!(comps.next(), Some(Component::Normal(_)));
    if comps.next().is_some() {
        return false;
    }
    let Some(first) = first else {
        return false;
    };
    is_listing_id(first)
        && has_second
        && (fs.listings.get(first).is_some() || fs.peer_knows_listing(first))
}

/// True if `path` is a single-component root-level path whose name
/// matches the listing-id shape (32 lowercase hex chars). Used by
/// rmdir to pick NotFound over PermissionDenied for well-formed but
/// unknown listing ids.
fn is_listing_id_shaped_single_component(path: &Path) -> bool {
    let mut comps = path.components();
    if comps.next() != Some(Component::RootDir) {
        return false;
    }
    let first = match comps.next() {
        Some(Component::Normal(s)) => s.to_str(),
        _ => return false,
    };
    if comps.next().is_some() {
        return false;
    }
    first.map(is_listing_id).unwrap_or(false)
}

/// Map a `BlobError` to a FUSE errno. Backend-opaque — the mount
/// layer doesn't try to recover from blob-store failure.
fn blob_to_errno(e: BlobError) -> FtFsError {
    warn!(err = ?e, "blob store error");
    FtFsError::Io
}

fn is_pubkey_hex(s: &str) -> bool {
    s.len() == PUBKEY_HEX_LEN && s.chars().all(|c| c.is_ascii_hexdigit()) && s.starts_with("04")
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
            | Some(ExtPath::OwnContractTemplateDir(_))
            | Some(ExtPath::UuidListing(_)) => Ok(self.attr_dir()),
            Some(ExtPath::UuidListingInfo(id)) => {
                // Serve the real byte-length so `ls -l` + readers
                // pick a sane buffer.
                let bytes = self.listing_info_bytes(&id)?;
                Ok(FtFileAttr {
                    size: bytes.len() as u64,
                    ..self.attr_file_empty()
                })
            }
            Some(ExtPath::OwnFileEntry(ref name)) => {
                // `ExtPath::parse` is syntactic — it returns
                // `OwnFileEntry` for ANY name under the own folder
                // that isn't a reserved subdir. We serve the real
                // byte-length from (in order): the in-flight
                // `PendingWrite` buffer, the `read_cache`, the
                // `size_cache` memo, and finally the slow chain
                // fetch + decrypt. The memo exists because
                // macOS/fuse-t polls getattr dozens of times per
                // second per entry during readdir — a chain round
                // trip every time would serialize behind the single
                // `NodeClient` mutex and stall concurrent writes.
                let pending_size = self
                    .pending_writes
                    .read()
                    .unwrap()
                    .get(name)
                    .map(|cell| cell.lock().unwrap().bytes.len() as u64);
                let cached_size = self
                    .read_cache
                    .read()
                    .unwrap()
                    .get(name)
                    .map(|v| v.len() as u64);
                let memo_size = self.size_cache.read().unwrap().get(name).copied();
                let times = self.times_cache.read().unwrap().get(name).cloned();
                let known = pending_size.or(cached_size).or(memo_size);
                if let Some(size) = known {
                    return Ok(self.attr_file_with(size, times));
                }
                // Cold path: fetch + decrypt + memoize so later
                // getattrs are O(1).
                match self.find_own_channel(name).ok() {
                    Some(channel) => match self.blobs.get(self.own_pubkey(), &channel) {
                        Ok(Some(bytes)) => {
                            let size = match self.try_decrypt(&bytes) {
                                Ok(unwrapped) => unwrapped.plaintext.len() as u64,
                                Err(_) => bytes.len() as u64,
                            };
                            self.size_cache.write().unwrap().insert(name.clone(), size);
                            Ok(self.attr_file_with(size, times))
                        }
                        _ => Err(FtFsError::NotFound),
                    },
                    None => Err(FtFsError::NotFound),
                }
            }
            Some(ExtPath::OwnContractTemplateFile { template, name }) => {
                // Contract-template drops are one-shot: a file at
                // `/me/<template>/<name>` only exists between
                // `create` and `release` — once released, it's
                // minted into a `/<uuid>/` listing and the
                // template path never resolves again. If no
                // `PendingWrite` is active for this (template,
                // name) key, surface `NotFound` so the kernel's
                // O_CREAT path routes to `create` instead of
                // open-looping on a ghost (same shape as the
                // `OwnFileEntry` ghost-file bug fixed above).
                let key = template_pending_key(template, &name);
                if self.pending_writes.read().unwrap().contains_key(&key) {
                    Ok(self.attr_file_empty())
                } else {
                    Err(FtFsError::NotFound)
                }
            }
            Some(ExtPath::OwnTokenFile { .. }) => Ok(self.attr_file_empty()),
            None => Err(FtFsError::NotFound),
        }
    }

    fn readdir(&self, path: &Path) -> FtFsResult<Vec<FtDirEntry>> {
        trace!(?path, "readdir");
        match ExtPath::parse(path, self) {
            Some(ExtPath::Root) => {
                // Daemon's own pubkey folder + every tracked foreign
                // folder + own listings + listings from each
                // tracked peer's on-chain manifest. Dedup by name so
                // a peer re-publishing the same id doesn't produce
                // two Finder entries.
                let mut entries: Vec<FtDirEntry> = Vec::new();
                entries.push(FtDirEntry::new(
                    self.own_pubkey().to_string(),
                    FileKind::Directory,
                ));
                for other in &self.tracked {
                    entries.push(FtDirEntry::new(other.clone(), FileKind::Directory));
                }
                for id in self.listings.ids() {
                    entries.push(FtDirEntry::new(id, FileKind::Directory));
                }
                for other in &self.tracked {
                    let manifest = self.fetch_peer_manifest(other);
                    for id in manifest.keys() {
                        entries.push(FtDirEntry::new(id.clone(), FileKind::Directory));
                    }
                }
                entries.sort_by(|a, b| a.name.cmp(&b.name));
                entries.dedup_by(|a, b| a.name == b.name);
                Ok(entries)
            }

            Some(ExtPath::OwnFolder) => {
                // The fixed children (`.tokens` + each registered
                // contract template) plus the user's own encrypted
                // blobs, decrypted here for display.
                let mut entries: Vec<FtDirEntry> = Vec::new();
                entries.push(FtDirEntry::new(TOKENS_DIR, FileKind::Directory));
                for template in self.registry.names() {
                    entries.push(FtDirEntry::new(template, FileKind::Directory));
                }
                for (plaintext_name, _channel) in self.list_own_entries()? {
                    entries.push(FtDirEntry::new(plaintext_name, FileKind::Regular));
                }
                entries.sort_by(|a, b| a.name.cmp(&b.name));
                entries.dedup_by(|a, b| a.name == b.name);
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

            Some(ExtPath::UuidListing(_)) => {
                // The one child a listing folder exposes is the
                // synthetic `.info` file. The real contract state
                // (purchase channel + encrypted blob) lives on-chain
                // and isn't surfaced through the mount surface.
                Ok(vec![FtDirEntry::new(LISTING_INFO_FILE, FileKind::Regular)])
            }

            Some(ExtPath::OwnTokenFile { .. })
            | Some(ExtPath::OwnFileEntry(_))
            | Some(ExtPath::OwnContractTemplateFile { .. })
            | Some(ExtPath::UuidListingInfo(_)) => Err(FtFsError::NotADirectory),

            None => Err(FtFsError::NotFound),
        }
    }

    fn open(&self, path: &Path, _flags: i32) -> FtFsResult<u64> {
        trace!(?path, "open");
        match ExtPath::parse(path, self) {
            Some(ExtPath::OwnFileEntry(name)) => {
                // Read-side: pre-fetch + decrypt once so subsequent
                // `read(offset, size)` calls are O(1). The envelope
                // isn't streamable, so we have to materialise the
                // whole plaintext anyway. `try_decrypt` handles
                // SELF (owner-wrote) and RECV (someone transferred
                // this to us) uniformly.
                let channel = self.find_own_channel(&name)?;
                let blob = self
                    .blobs
                    .get(self.own_pubkey(), &channel)
                    .map_err(blob_to_errno)?
                    .ok_or(FtFsError::NotFound)?;
                let unwrapped = self.try_decrypt(&blob)?;
                let size = unwrapped.plaintext.len() as u64;
                self.read_cache
                    .write()
                    .unwrap()
                    .insert(name.clone(), unwrapped.plaintext);
                self.size_cache.write().unwrap().insert(name.clone(), size);
                // Touch atime on open-for-read; preserve mtime +
                // ctime if we already know them.
                let now = SystemTime::now();
                let mut tc = self.times_cache.write().unwrap();
                let (_, mtime, ctime) = tc.get(&name).cloned().unwrap_or((now, now, now));
                tc.insert(name, (now, mtime, ctime));
                Ok(self
                    .next_fh
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed))
            }
            Some(ExtPath::UuidListingInfo(_)) => {
                // Synthetic file; `read` materialises on each call,
                // no cache entry needed.
                Ok(self
                    .next_fh
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed))
            }
            Some(ExtPath::OwnTokenFile { .. }) => Ok(0),
            _ => Err(FtFsError::NotFound),
        }
    }

    fn read(&self, path: &Path, offset: u64, size: usize, _fh: u64) -> FtFsResult<Vec<u8>> {
        match ExtPath::parse(path, self) {
            Some(ExtPath::OwnFileEntry(name)) => {
                let cache = self.read_cache.read().unwrap();
                let full = cache.get(&name).ok_or(FtFsError::NotFound)?;
                let start = offset as usize;
                if start >= full.len() {
                    return Ok(Vec::new());
                }
                let end = (start + size).min(full.len());
                Ok(full[start..end].to_vec())
            }
            Some(ExtPath::UuidListingInfo(id)) => {
                let bytes = self.listing_info_bytes(&id)?;
                let start = offset as usize;
                if start >= bytes.len() {
                    return Ok(Vec::new());
                }
                let end = (start + size).min(bytes.len());
                Ok(bytes[start..end].to_vec())
            }
            Some(ExtPath::OwnTokenFile { .. }) => Ok(Vec::new()),
            _ => Err(FtFsError::NotFound),
        }
    }

    fn release(&self, path: &Path, _fh: u64) -> FtFsResult<()> {
        trace!(?path, "release");
        // On close, (a) if a pending write buffered any bytes,
        // encrypt + persist them (regular file) or mint a listing
        // (contract-template drop), and (b) drop the read cache slot
        // so re-opening fetches fresh.
        match ExtPath::parse(path, self) {
            Some(ExtPath::OwnFileEntry(name)) => {
                // Capture the current blob's channel BEFORE
                // flushing. flush_pending mints a fresh K and a
                // fresh channel; the old blob (if any) would
                // otherwise linger and show up as a duplicate in
                // readdir. Covers both own SELF edits and recipient
                // edits of a RECV blob (effectively RECV→SELF
                // ownership transfer).
                let old_channel = self.find_own_channel(&name).ok();
                let pending = self.pending_writes.write().unwrap().remove(&name);
                if let Some(cell) = pending {
                    let pw = cell.into_inner().unwrap();
                    let final_size = pw.bytes.len() as u64;
                    let new_channel = self.flush_pending(&name, &pw)?;
                    self.gc_replaced_blob(old_channel.as_deref(), &new_channel);
                    self.size_cache
                        .write()
                        .unwrap()
                        .insert(name.clone(), final_size);
                }
                self.read_cache.write().unwrap().remove(&name);
            }
            Some(ExtPath::OwnContractTemplateFile { template, name }) => {
                let key = template_pending_key(template, &name);
                let pending = self.pending_writes.write().unwrap().remove(&key);
                if let Some(cell) = pending {
                    let pw = cell.into_inner().unwrap();
                    self.mint_listing_from_drop(template, &name, &pw.bytes)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn flush(&self, path: &Path, _fh: u64) -> FtFsResult<()> {
        // Same as release's write-side path, but doesn't drop the
        // read cache — fsync-style, callers may still read after.
        // Contract-template drops aren't flush-safe: the mint
        // happens on release only, so a mid-write flush is a no-op.
        if let Some(ExtPath::OwnFileEntry(name)) = ExtPath::parse(path, self) {
            let has_pending = self.pending_writes.read().unwrap().contains_key(&name);
            if has_pending {
                let old_channel = self.find_own_channel(&name).ok();
                let pending = self.pending_writes.write().unwrap().remove(&name);
                if let Some(cell) = pending {
                    let pw = cell.into_inner().unwrap();
                    let new_channel = self.flush_pending(&name, &pw)?;
                    self.gc_replaced_blob(old_channel.as_deref(), &new_channel);
                }
            }
        }
        Ok(())
    }

    fn create(&self, path: &Path, _mode: u32, _flags: i32) -> FtFsResult<u64> {
        trace!(?path, "create");
        match ExtPath::parse(path, self) {
            Some(ExtPath::OwnFileEntry(name)) => {
                self.pending_writes.write().unwrap().insert(
                    name.clone(),
                    Mutex::new(PendingWrite {
                        bytes: Vec::new(),
                        cipher_channel: None,
                    }),
                );
                let now = SystemTime::now();
                self.times_cache
                    .write()
                    .unwrap()
                    .insert(name.clone(), (now, now, now));
                Ok(self
                    .next_fh
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed))
            }
            Some(ExtPath::OwnContractTemplateFile { template, name }) => {
                // Validate the filename against the template now,
                // before FUSE spools any writes. A malformed name
                // (e.g. `/<me>/Paid transfer/not-a-price.txt`)
                // short-circuits here rather than wasting an upload.
                let template_impl = self.registry.find(template).ok_or(FtFsError::NotFound)?;
                if template_impl.parse(&name).is_none() {
                    tracing::warn!(
                        template,
                        name,
                        "contract-template drop with malformed filename rejected"
                    );
                    return Err(FtFsError::InvalidArgument);
                }
                let key = template_pending_key(template, &name);
                self.pending_writes.write().unwrap().insert(
                    key,
                    Mutex::new(PendingWrite {
                        bytes: Vec::new(),
                        cipher_channel: None,
                    }),
                );
                Ok(self
                    .next_fh
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed))
            }
            _ => Err(FtFsError::PermissionDenied),
        }
    }

    fn write(&self, path: &Path, offset: u64, data: &[u8], _fh: u64) -> FtFsResult<usize> {
        trace!(?path, offset, len = data.len(), "write");
        match ExtPath::parse(path, self) {
            Some(ExtPath::OwnFileEntry(name)) => {
                // Lazy-promote an existing file to a pending-write
                // buffer if the user opens-for-write + writes
                // without a prior `create`. We treat that as "edit
                // in place": fetch current plaintext, let the user
                // overwrite from offset.
                let needs_init = !self.pending_writes.read().unwrap().contains_key(&name);
                if needs_init {
                    // Prime the buffer with the current plaintext (if any).
                    let existing = self
                        .read_cache
                        .read()
                        .unwrap()
                        .get(&name)
                        .cloned()
                        .unwrap_or_default();
                    self.pending_writes.write().unwrap().insert(
                        name.clone(),
                        Mutex::new(PendingWrite {
                            bytes: existing,
                            cipher_channel: None,
                        }),
                    );
                }
                let g = self.pending_writes.read().unwrap();
                let cell = g.get(&name).ok_or(FtFsError::Io)?;
                let mut pw = cell.lock().unwrap();
                let end = offset as usize + data.len();
                if pw.bytes.len() < end {
                    pw.bytes.resize(end, 0);
                }
                pw.bytes[offset as usize..end].copy_from_slice(data);
                let new_size = pw.bytes.len() as u64;
                drop(pw);
                drop(g);
                self.size_cache
                    .write()
                    .unwrap()
                    .insert(name.clone(), new_size);
                // Bump mtime (and ctime, since the content changed)
                // on every write chunk. Preserve atime if we already
                // have one from create/open.
                let now = SystemTime::now();
                let mut tc = self.times_cache.write().unwrap();
                let (atime, _, _) = tc.get(&name).cloned().unwrap_or((now, now, now));
                tc.insert(name, (atime, now, now));
                Ok(data.len())
            }
            Some(ExtPath::OwnContractTemplateFile { template, name }) => {
                let key = template_pending_key(template, &name);
                let g = self.pending_writes.read().unwrap();
                let cell = g.get(&key).ok_or(FtFsError::Io)?;
                let mut pw = cell.lock().unwrap();
                let end = offset as usize + data.len();
                if pw.bytes.len() < end {
                    pw.bytes.resize(end, 0);
                }
                pw.bytes[offset as usize..end].copy_from_slice(data);
                Ok(data.len())
            }
            _ => Err(FtFsError::PermissionDenied),
        }
    }

    fn truncate(&self, path: &Path, size: u64) -> FtFsResult<()> {
        match ExtPath::parse(path, self) {
            Some(ExtPath::OwnFileEntry(name)) => {
                // Truncate on an open file: resize the pending-write
                // buffer. If there's no pending write yet, create
                // one so a subsequent `write` plus release will
                // emit a correctly-shortened envelope.
                let mut g = self.pending_writes.write().unwrap();
                let cell = g.entry(name).or_insert_with(|| {
                    Mutex::new(PendingWrite {
                        bytes: Vec::new(),
                        cipher_channel: None,
                    })
                });
                let pw = cell.get_mut().unwrap();
                pw.bytes.resize(size as usize, 0);
                Ok(())
            }
            _ => Err(FtFsError::PermissionDenied),
        }
    }

    fn chmod(&self, _path: &Path, _mode: u32) -> FtFsResult<()> {
        Err(FtFsError::PermissionDenied)
    }
    fn mkdir(&self, _path: &Path, _mode: u32) -> FtFsResult<()> {
        // ADR-0002: mkdir at root is restricted to pubkey folders
        // (auto-provisioned at startup) and uuid listings (minted
        // by the Paid-transfer factory in slice 7). We never accept
        // user-initiated mkdir, period.
        Err(FtFsError::PermissionDenied)
    }
    fn unlink(&self, path: &Path) -> FtFsResult<()> {
        // ADR-0002: only the owner can delete their own files. The
        // on-chain blob is addressed by the owner's prefix, so even
        // if the kernel passed us a nested foreign path we'd refuse
        // the deploy as not-ours.
        match ExtPath::parse(path, self) {
            Some(ExtPath::OwnFileEntry(name)) => {
                let channel = self.find_own_channel(&name)?;
                let fp = self.self_key_fingerprint(&channel);
                self.blobs
                    .delete(self.own_pubkey(), &channel)
                    .map_err(blob_to_errno)?;
                self.read_cache.write().unwrap().remove(&name);
                self.pending_writes.write().unwrap().remove(&name);
                self.size_cache.write().unwrap().remove(&name);
                self.times_cache.write().unwrap().remove(&name);
                if let Some(fp) = fp {
                    self.gc_orphaned_key(&fp);
                }
                Ok(())
            }
            _ => Err(FtFsError::PermissionDenied),
        }
    }
    fn rmdir(&self, path: &Path) -> FtFsResult<()> {
        // ADR-0002: pubkey folders + contract-template folders stay
        // undeletable. The one deletable directory shape is a
        // listing uuid folder, and only its owner can rmdir.
        match ExtPath::parse(path, self) {
            Some(ExtPath::UuidListing(id)) => {
                let listing = self.listings.get(&id).ok_or(FtFsError::NotFound)?;
                if listing.owner_pubkey_hex != self.own_pubkey() {
                    tracing::warn!(
                        caller = %self.own_pubkey(),
                        owner = %listing.owner_pubkey_hex,
                        listing_id = %id,
                        "rmdir on listing not owned by caller — denied"
                    );
                    return Err(FtFsError::PermissionDenied);
                }
                // If the listing lives on-chain, burn it there. The
                // factory's own owner-check will also reject non-owner
                // callers, but we already filter above so this is
                // the owner's deploy.
                match (listing.listing_uri.as_deref(), self.factory.as_ref()) {
                    (Some(uri), Some(factory)) => {
                        factory.rmdir_listing(uri).map_err(|e| {
                            warn!(err = ?e, listing_id = %id, "factory rmdir deploy failed");
                            FtFsError::Io
                        })?;
                    }
                    _ => {
                        // Local path: the ciphertext lives under the
                        // owner's prefix at channel == listing id.
                        let fp = self.self_key_fingerprint(&id);
                        self.blobs
                            .delete(self.own_pubkey(), &id)
                            .map_err(blob_to_errno)?;
                        if let Some(fp) = fp {
                            self.gc_orphaned_key(&fp);
                        }
                    }
                }
                self.listings.remove(&id);
                self.publish_own_manifest();
                tracing::info!(listing_id = %id, "rmdir listing");
                Ok(())
            }
            None => {
                // Could be a well-formed listing-shaped path with no
                // matching listing — surface that as NotFound rather
                // than PermissionDenied so POSIX-y tooling behaves.
                if is_listing_id_shaped_single_component(path) {
                    Err(FtFsError::NotFound)
                } else {
                    Err(FtFsError::PermissionDenied)
                }
            }
            _ => Err(FtFsError::PermissionDenied),
        }
    }
    fn rename(&self, from: &Path, to: &Path) -> FtFsResult<()> {
        trace!(?from, ?to, "rename");
        // Accepted rename shapes:
        //   /<own>/<a>  →  /<own>/<b>
        //     - SELF source: re-wrap under same K with new filename
        //     - RECV source: RECV→SELF ownership transfer under a
        //       fresh K minted locally
        //   /<own>/<a>  →  /<peer>/<b>
        //     - SELF source: SELF→RECV transfer (new K minted inside
        //       wrap_recv, ECIES-wrapped for recipient)
        //     - RECV source: RECV→RECV forwarding (new K minted,
        //       re-wrapped for the new recipient)
        // Anything else returns EPERM.
        //
        // Token drops onto a listing — `rename /<me>/.tokens/<bill>
        // → /<listing>/<x>` — are the ADR-0002 purchase path. If a
        // FactoryClient is attached + the listing has a URI, invoke
        // `paid_transfer_purchase` on the factory, then locally
        // re-wrap the released blob as a RECV under the buyer's
        // prefix so it shows up in the buyer's folder on next
        // readdir. The REV transfer runs inside the factory as part
        // of the deploy.
        if looks_like_token_drop_onto_listing(from, to, self) {
            return self.purchase_via_factory(from, to);
        }
        let Some(ExtPath::OwnFileEntry(from_name)) = ExtPath::parse(from, self) else {
            return Err(FtFsError::PermissionDenied);
        };
        let (dest_pubkey, dest_filename) = parse_pubkey_file_destination(to, &self.registry)?;

        let channel = self.find_own_channel(&from_name)?;
        let blob = self
            .blobs
            .get(self.own_pubkey(), &channel)
            .map_err(blob_to_errno)?
            .ok_or(FtFsError::NotFound)?;

        // Classify the source envelope. Anything that isn't SELF
        // or RECV we can't decrypt — refuse with EPERM.
        let source_is_self = blob.len() >= 4 && &blob[..4] == b"SELF";
        let source_is_recv = blob.len() >= 4 && &blob[..4] == b"RECV";
        if !(source_is_self || source_is_recv) {
            tracing::warn!(
                blob_tag = ?blob.get(..4),
                "rename on blob with unknown tag"
            );
            return Err(FtFsError::PermissionDenied);
        }
        let unwrapped = self.try_decrypt(&blob)?;

        let (new_envelope_bytes, dest_prefix) = if dest_pubkey == self.own_pubkey() {
            // Destination is own folder. SELF-source: reuse K to
            // keep the keystore from bloating on each rename. RECV-
            // source: mint a fresh K and promote to SELF (ownership
            // transfer — we're taking ownership of a file someone
            // else wrapped for us).
            let k = if source_is_self {
                self.self_key_for(&blob)?
            } else {
                let key = generate_key();
                self.keystore.store(&key).map_err(|_| FtFsError::Io)?;
                key
            };
            let (env, _fp) = envelope::wrap_self(&k, &dest_filename, &unwrapped.plaintext)
                .map_err(|_| FtFsError::Io)?;
            (env.bytes, self.own_pubkey().to_string())
        } else {
            // Destination is a peer folder. Both SELF-source and
            // RECV-source produce a fresh RECV wrapped for the new
            // recipient. For SELF→RECV this is a transfer; for
            // RECV→RECV it's a forward.
            let recipient_pubkey_bytes = hex::decode(&dest_pubkey).map_err(|_| {
                tracing::warn!(dest_pubkey, "destination folder is not valid hex");
                FtFsError::InvalidArgument
            })?;
            let env = envelope::wrap_recv(
                &recipient_pubkey_bytes,
                &dest_filename,
                &unwrapped.plaintext,
            )
            .map_err(|_| FtFsError::Io)?;
            (env.bytes, dest_pubkey)
        };

        let new_channel = cipher_channel_for(&new_envelope_bytes);
        self.blobs
            .put(&dest_prefix, &new_channel, &new_envelope_bytes)
            .map_err(blob_to_errno)?;
        self.blobs
            .delete(self.own_pubkey(), &channel)
            .map_err(blob_to_errno)?;

        // Drop the old read-cache slot so a subsequent read of the
        // new name hits the fresh blob.
        self.read_cache.write().unwrap().remove(&from_name);
        Ok(())
    }
}

/// Parse `/<pubkey-hex>/<filename>` into `(pubkey_hex_lowercase, filename)`.
/// Accepts any 130-char lowercase hex folder, even if the daemon isn't
/// tracking it — rename-across-folders is the way to initiate a
/// transfer to someone we don't normally render in `readdir /`.
fn parse_pubkey_file_destination(
    path: &Path,
    registry: &ContractRegistry,
) -> FtFsResult<(String, String)> {
    let mut comps = path.components();
    if comps.next() != Some(Component::RootDir) {
        return Err(FtFsError::InvalidArgument);
    }
    let segs: Vec<&str> = comps
        .map(|c| match c {
            Component::Normal(s) => s.to_str(),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(FtFsError::InvalidArgument)?;
    match segs.as_slice() {
        [pubkey, name] => {
            let folder = pubkey.to_lowercase();
            if !is_pubkey_hex(&folder) {
                return Err(FtFsError::InvalidArgument);
            }
            // Reserved subshape names can't double as transfer
            // filenames — if the user tries to rename *into*
            // `.tokens/x` we'd clash with the token subtree.
            if *name == TOKENS_DIR || registry.find(name).is_some() {
                return Err(FtFsError::PermissionDenied);
            }
            Ok((folder, (*name).to_string()))
        }
        _ => Err(FtFsError::InvalidArgument),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract_template::ListingSpec;

    fn make_fs(tracked: Vec<String>) -> ExtensionFs {
        let tmp = tempfile::tempdir().unwrap();
        let identity = Arc::new(Identity::load_or_create(tmp.path()).unwrap());
        let blobs: Arc<dyn BlobStore> = Arc::new(crate::blob_store::InMemoryBlobStore::new());
        let keystore = Arc::new(Keystore::open(tmp.path()).unwrap());
        let fs = ExtensionFs::new(
            identity,
            tracked,
            ExtensionFsConfig::default(),
            blobs,
            keystore,
        );
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
    fn unlink_removes_own_file() {
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        let p = format!("/{own}/notes.txt");
        let path = Path::new(&p);
        let fh = fs.create(path, 0o644, 0).unwrap();
        fs.write(path, 0, b"hello", fh).unwrap();
        fs.release(path, fh).unwrap();

        fs.unlink(path).unwrap();

        // Readdir no longer surfaces the deleted file.
        let entries = fs.readdir(Path::new(&format!("/{own}"))).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(!names.contains(&"notes.txt"));
    }

    #[test]
    fn unlink_gcs_the_orphaned_keystore_entry() {
        // Each own-file write mints a fresh symmetric key stored in
        // the keystore. On unlink, the key becomes orphaned (no
        // blob references it anymore) and the daemon should drop
        // the keystore entry.
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        let p = format!("/{own}/alpha.txt");
        let path = Path::new(&p);
        let fh = fs.create(path, 0o644, 0).unwrap();
        fs.write(path, 0, b"body", fh).unwrap();
        fs.release(path, fh).unwrap();
        assert_eq!(fs.keystore.len().unwrap(), 1);

        fs.unlink(path).unwrap();

        assert_eq!(
            fs.keystore.len().unwrap(),
            0,
            "keystore entry should be GC'd when its last-referring blob is unlinked"
        );
    }

    #[test]
    fn edit_replace_gcs_the_old_keystore_entry() {
        // v1 write + unlink flow leaves one key in the keystore.
        // Edit (lazy-promote path) writes a fresh K, replaces the
        // blob; the OLD K becomes orphaned and should be dropped.
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        let p = format!("/{own}/edit.txt");
        let path = Path::new(&p);
        let fh = fs.create(path, 0o644, 0).unwrap();
        fs.write(path, 0, b"v1", fh).unwrap();
        fs.release(path, fh).unwrap();
        assert_eq!(fs.keystore.len().unwrap(), 1);

        // Lazy-promote edit.
        let fh = fs.open(path, 0).unwrap();
        let _ = fs.read(path, 0, 100, fh).unwrap();
        fs.write(path, 0, b"version two", fh).unwrap();
        fs.release(path, fh).unwrap();

        assert_eq!(
            fs.keystore.len().unwrap(),
            1,
            "post-edit keystore should contain exactly the new K, not both"
        );
    }

    #[test]
    fn unlink_missing_returns_not_found() {
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        let p = format!("/{own}/never-created");
        assert!(matches!(fs.unlink(Path::new(&p)), Err(FtFsError::NotFound),));
    }

    #[test]
    fn unlink_in_foreign_folder_denied() {
        let foreign = format!("04{}", "ab".repeat(64));
        let fs = make_fs(vec![foreign.clone()]);
        let p = format!("/{foreign}/anything");
        assert!(matches!(
            fs.unlink(Path::new(&p)),
            Err(FtFsError::PermissionDenied),
        ));
    }

    #[test]
    fn rename_within_own_folder_preserves_content() {
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        let from = format!("/{own}/old.txt");
        let to = format!("/{own}/new.txt");
        let fh = fs.create(Path::new(&from), 0o644, 0).unwrap();
        fs.write(Path::new(&from), 0, b"stable", fh).unwrap();
        fs.release(Path::new(&from), fh).unwrap();

        fs.rename(Path::new(&from), Path::new(&to)).unwrap();

        // Old name is gone from readdir, new name is present.
        let entries = fs.readdir(Path::new(&format!("/{own}"))).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(!names.contains(&"old.txt"));
        assert!(names.contains(&"new.txt"));

        // Content survives.
        let fh2 = fs.open(Path::new(&to), 0).unwrap();
        assert_eq!(fs.read(Path::new(&to), 0, 100, fh2).unwrap(), b"stable");
    }

    #[test]
    fn rename_across_folders_rewraps_as_recv_for_recipient() {
        // Set up a second identity and have the daemon do a transfer
        // to it. The recipient's daemon (fs_b) sees the RECV blob
        // under its own prefix and can decrypt + read it.
        let state_b = tempfile::tempdir().unwrap();
        let identity_b = Arc::new(Identity::load_or_create(state_b.path()).unwrap());
        let recipient = identity_b.pubkey_hex().to_string();

        // Shared blob store so both daemons see the same on-chain state.
        let blobs: Arc<dyn BlobStore> = Arc::new(crate::blob_store::InMemoryBlobStore::new());

        // Sender daemon (fs_a).
        let state_a = tempfile::tempdir().unwrap();
        let identity_a = Arc::new(Identity::load_or_create(state_a.path()).unwrap());
        let keystore_a = Arc::new(Keystore::open(state_a.path()).unwrap());
        let fs_a = ExtensionFs::new(
            Arc::clone(&identity_a),
            vec![],
            ExtensionFsConfig::default(),
            Arc::clone(&blobs),
            keystore_a,
        );

        // Recipient daemon (fs_b).
        let keystore_b = Arc::new(Keystore::open(state_b.path()).unwrap());
        let fs_b = ExtensionFs::new(
            Arc::clone(&identity_b),
            vec![],
            ExtensionFsConfig::default(),
            Arc::clone(&blobs),
            keystore_b,
        );

        // Sender creates a file + writes content.
        let own_a = identity_a.pubkey_hex().to_string();
        let src = format!("/{own_a}/transfer.txt");
        let fh = fs_a.create(Path::new(&src), 0o644, 0).unwrap();
        fs_a.write(Path::new(&src), 0, b"a secret payload", fh)
            .unwrap();
        fs_a.release(Path::new(&src), fh).unwrap();

        // Rename across folders → SELF→RECV re-wrap.
        let dst = format!("/{recipient}/incoming.txt");
        fs_a.rename(Path::new(&src), Path::new(&dst)).unwrap();

        // Sender no longer sees the file in their folder.
        let a_entries = fs_a.readdir(Path::new(&format!("/{own_a}"))).unwrap();
        let a_names: Vec<&str> = a_entries.iter().map(|e| e.name.as_str()).collect();
        assert!(!a_names.contains(&"transfer.txt"));

        // Recipient sees it under their own folder with the new name.
        let b_entries = fs_b.readdir(Path::new(&format!("/{recipient}"))).unwrap();
        let b_names: Vec<&str> = b_entries.iter().map(|e| e.name.as_str()).collect();
        assert!(b_names.contains(&"incoming.txt"));

        // Recipient can open + read the plaintext.
        let path_b = format!("/{recipient}/incoming.txt");
        let fh_b = fs_b.open(Path::new(&path_b), 0).unwrap();
        assert_eq!(
            fs_b.read(Path::new(&path_b), 0, 100, fh_b).unwrap(),
            b"a secret payload"
        );

        std::mem::forget(state_a);
        std::mem::forget(state_b);
    }

    #[test]
    fn rename_from_foreign_folder_is_denied() {
        let foreign = format!("04{}", "ab".repeat(64));
        let fs = make_fs(vec![foreign.clone()]);
        let own = fs.own_pubkey().to_string();
        let from = format!("/{foreign}/something");
        let to = format!("/{own}/stolen");
        assert!(matches!(
            fs.rename(Path::new(&from), Path::new(&to)),
            Err(FtFsError::PermissionDenied),
        ));
    }

    #[test]
    fn rename_to_reserved_name_denied() {
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        let from = format!("/{own}/payload");
        let path = Path::new(&from);
        let fh = fs.create(path, 0o644, 0).unwrap();
        fs.write(path, 0, b"data", fh).unwrap();
        fs.release(path, fh).unwrap();

        // Can't rename over the .tokens subshape name.
        let to_tokens = format!("/{own}/{TOKENS_DIR}");
        assert!(matches!(
            fs.rename(path, Path::new(&to_tokens)),
            Err(FtFsError::PermissionDenied),
        ));
        // Can't rename over a contract-template folder either.
        let to_template = format!("/{own}/{PAID_TRANSFER_DIR}");
        assert!(matches!(
            fs.rename(path, Path::new(&to_template)),
            Err(FtFsError::PermissionDenied),
        ));
    }

    #[test]
    fn drop_into_paid_transfer_mints_listing_at_root() {
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        let p = format!("/{own}/{PAID_TRANSFER_DIR}/10REV-notes.txt");
        let path = Path::new(&p);

        // Precondition: no listings yet; root has only the owner's folder.
        let before = fs.readdir(Path::new("/")).unwrap();
        let before_names: Vec<&str> = before.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(before_names, vec![own.as_str()]);

        // Drop a file in — equivalent to a drag-and-drop into the Paid-transfer folder.
        let fh = fs.create(path, 0o644, 0).unwrap();
        fs.write(path, 0, b"the-content", fh).unwrap();
        fs.release(path, fh).unwrap();

        // Root readdir now surfaces a 32-char hex listing folder.
        let after = fs.readdir(Path::new("/")).unwrap();
        let listing_names: Vec<String> = after
            .iter()
            .map(|e| e.name.clone())
            .filter(|n| n != &own)
            .collect();
        assert_eq!(listing_names.len(), 1);
        let id = &listing_names[0];
        assert!(crate::contract_template::is_listing_id(id));

        // The listing in the store carries the parsed spec and owner.
        let listing = fs.listings.get(id).expect("listing should be recorded");
        assert_eq!(listing.owner_pubkey_hex, own);
        assert_eq!(listing.template_name, "Paid transfer");
        assert_eq!(
            listing.spec,
            ListingSpec::PaidTransfer {
                price: 10,
                filename: "notes.txt".into(),
            }
        );

        // The uuid folder is reachable + looks like a dir.
        let listing_path = format!("/{id}");
        let attr = fs.getattr(Path::new(&listing_path)).unwrap();
        assert_eq!(attr.kind, FileKind::Directory);
        // Slice 11+: readdir on the uuid folder exposes a `.info`
        // file so buyers can inspect the listing before purchasing.
        let entries = fs.readdir(Path::new(&listing_path)).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec![LISTING_INFO_FILE]);
    }

    #[test]
    fn drop_with_malformed_filename_rejected_at_create() {
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        // Not `<N>REV-<rest>` — reject before any writes land.
        let p = format!("/{own}/{PAID_TRANSFER_DIR}/not-a-listing.txt");
        assert!(matches!(
            fs.create(Path::new(&p), 0o644, 0),
            Err(FtFsError::InvalidArgument),
        ));
        // And no listing was minted.
        assert!(fs.listings.is_empty());
    }

    #[test]
    fn drop_into_unknown_template_folder_is_not_found() {
        // The parser treats unknown second-level names in own-folder
        // as OwnFileEntry, so a nested path there has no legal shape.
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        let p = format!("/{own}/NoSuchTemplate/10REV-x.txt");
        assert!(matches!(
            fs.create(Path::new(&p), 0o644, 0),
            Err(FtFsError::PermissionDenied),
        ));
    }

    #[test]
    fn getattr_on_untracked_listing_id_is_not_found() {
        let fs = make_fs(vec![]);
        // 32 hex chars but no matching listing in the store.
        let p = format!("/{}", "ff".repeat(16));
        assert!(matches!(
            fs.getattr(Path::new(&p)),
            Err(FtFsError::NotFound),
        ));
    }

    #[test]
    fn paid_transfer_folder_readdir_still_empty() {
        // Drops happen at create+write+release; readdir on the
        // template subfolder itself remains empty (there's no
        // persistent files there — the mint goes straight to a uuid).
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        let p = format!("/{own}/{PAID_TRANSFER_DIR}/20REV-x.txt");
        let path = Path::new(&p);
        let fh = fs.create(path, 0o644, 0).unwrap();
        fs.write(path, 0, b"", fh).unwrap();
        fs.release(path, fh).unwrap();

        let entries = fs
            .readdir(Path::new(&format!("/{own}/{PAID_TRANSFER_DIR}")))
            .unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn drop_persists_encrypted_blob_under_listing_channel() {
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        let p = format!("/{own}/{PAID_TRANSFER_DIR}/7REV-manuscript.pdf");
        let path = Path::new(&p);

        let fh = fs.create(path, 0o644, 0).unwrap();
        fs.write(path, 0, b"draft chapter one", fh).unwrap();
        fs.release(path, fh).unwrap();

        // Grab the minted listing id out of the store, then confirm
        // the blob is actually in the BlobStore under that channel.
        let ids = fs.listings.ids();
        assert_eq!(ids.len(), 1);
        let id = &ids[0];
        let blob = fs
            .blobs
            .get(&own, id)
            .unwrap()
            .expect("listing envelope should be persisted on-chain");
        // Must be a SELF envelope — the owner's daemon wrapped it.
        assert_eq!(&blob[..4], b"SELF");
        // And the daemon can decrypt it back to the dropped bytes +
        // the plaintext filename parsed out by the template.
        let unwrapped = fs.decrypt_self(&blob).unwrap();
        assert_eq!(unwrapped.filename, "manuscript.pdf");
        assert_eq!(unwrapped.plaintext, b"draft chapter one");
    }

    #[test]
    fn listing_blob_is_hidden_from_owner_folder_readdir() {
        // The listing's SELF blob is stored under the owner's prefix
        // but shouldn't show up as a regular file in their folder —
        // the uuid folder at root is the primary interface.
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        let p = format!("/{own}/{PAID_TRANSFER_DIR}/3REV-receipt.txt");
        let path = Path::new(&p);
        let fh = fs.create(path, 0o644, 0).unwrap();
        fs.write(path, 0, b"hi", fh).unwrap();
        fs.release(path, fh).unwrap();

        let entries = fs.readdir(Path::new(&format!("/{own}"))).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        // No `receipt.txt` in the owner's folder — the listing is
        // the user-visible surface, not the raw blob.
        assert!(!names.contains(&"receipt.txt"));
        // Only the fixed children (.tokens + "Paid transfer") remain.
        assert!(names.contains(&TOKENS_DIR));
        assert!(names.contains(&PAID_TRANSFER_DIR));
    }

    #[test]
    fn owner_can_rmdir_listing() {
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        let p = format!("/{own}/{PAID_TRANSFER_DIR}/1REV-byebye.txt");
        let path = Path::new(&p);
        let fh = fs.create(path, 0o644, 0).unwrap();
        fs.write(path, 0, b"content", fh).unwrap();
        fs.release(path, fh).unwrap();

        let id = fs.listings.ids().into_iter().next().unwrap();
        let listing_path = format!("/{id}");

        // Precondition: listing + blob both present.
        assert!(fs.listings.get(&id).is_some());
        assert!(fs.blobs.get(&own, &id).unwrap().is_some());

        fs.rmdir(Path::new(&listing_path)).unwrap();

        // Postcondition: both gone. The uuid is no longer reachable.
        assert!(fs.listings.get(&id).is_none());
        assert!(fs.blobs.get(&own, &id).unwrap().is_none());
        assert!(matches!(
            fs.getattr(Path::new(&listing_path)),
            Err(FtFsError::NotFound),
        ));
    }

    #[test]
    fn rmdir_listing_denied_for_non_owner() {
        // Two daemons sharing a blob store. Alice mints the listing;
        // Bob tries to rmdir it. The daemon on Bob's side has its
        // own listing store (synthetically populated here to
        // simulate what a shared on-chain listing index would look
        // like once slice 9 wires it up).
        let state_a = tempfile::tempdir().unwrap();
        let state_b = tempfile::tempdir().unwrap();
        let id_a = Arc::new(Identity::load_or_create(state_a.path()).unwrap());
        let id_b = Arc::new(Identity::load_or_create(state_b.path()).unwrap());
        let blobs: Arc<dyn BlobStore> = Arc::new(crate::blob_store::InMemoryBlobStore::new());
        let shared_listings = Arc::new(ListingStore::new());

        let fs_alice = ExtensionFs::with_registry(
            Arc::clone(&id_a),
            vec![],
            ExtensionFsConfig::default(),
            Arc::clone(&blobs),
            Arc::new(Keystore::open(state_a.path()).unwrap()),
            Arc::new(ContractRegistry::new()),
            Arc::clone(&shared_listings),
        );
        let fs_bob = ExtensionFs::with_registry(
            Arc::clone(&id_b),
            vec![],
            ExtensionFsConfig::default(),
            Arc::clone(&blobs),
            Arc::new(Keystore::open(state_b.path()).unwrap()),
            Arc::new(ContractRegistry::new()),
            Arc::clone(&shared_listings),
        );

        // Alice mints a listing.
        let own_a = id_a.pubkey_hex().to_string();
        let p = format!("/{own_a}/{PAID_TRANSFER_DIR}/2REV-mine.txt");
        let path = Path::new(&p);
        let fh = fs_alice.create(path, 0o644, 0).unwrap();
        fs_alice.write(path, 0, b"owned", fh).unwrap();
        fs_alice.release(path, fh).unwrap();

        let id = shared_listings.ids().into_iter().next().unwrap();

        // Bob tries to rmdir it. His daemon sees the listing in the
        // shared store but refuses because the owner isn't him.
        let listing_path = format!("/{id}");
        assert!(matches!(
            fs_bob.rmdir(Path::new(&listing_path)),
            Err(FtFsError::PermissionDenied),
        ));

        // The blob is still there on-chain.
        assert!(blobs.get(&own_a, &id).unwrap().is_some());

        std::mem::forget(state_a);
        std::mem::forget(state_b);
    }

    #[test]
    fn rmdir_on_unknown_listing_is_not_found() {
        let fs = make_fs(vec![]);
        // Well-formed listing id, but not in the store.
        let p = format!("/{}", "ab".repeat(16));
        assert!(matches!(fs.rmdir(Path::new(&p)), Err(FtFsError::NotFound),));
    }

    #[test]
    fn rmdir_on_own_folder_still_denied() {
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        assert!(matches!(
            fs.rmdir(Path::new(&format!("/{own}"))),
            Err(FtFsError::PermissionDenied),
        ));
    }

    #[test]
    fn tracked_peer_listings_appear_in_root_readdir() {
        // Two daemons sharing a BlobStore. Bob tracks Alice's
        // pubkey. Alice drops a file. Bob's readdir / surfaces the
        // listing uuid even though his local ListingStore never
        // saw it — the on-chain manifest is the source of truth
        // for cross-daemon discovery.
        let state_a = tempfile::tempdir().unwrap();
        let state_b = tempfile::tempdir().unwrap();
        let id_a = Arc::new(Identity::load_or_create(state_a.path()).unwrap());
        let id_b = Arc::new(Identity::load_or_create(state_b.path()).unwrap());
        let blobs: Arc<dyn BlobStore> = Arc::new(crate::blob_store::InMemoryBlobStore::new());

        let fs_alice = ExtensionFs::with_registry(
            Arc::clone(&id_a),
            vec![],
            ExtensionFsConfig::default(),
            Arc::clone(&blobs),
            Arc::new(Keystore::open(state_a.path()).unwrap()),
            Arc::new(ContractRegistry::new()),
            Arc::new(ListingStore::new()),
        );
        let fs_bob = ExtensionFs::with_registry(
            Arc::clone(&id_b),
            vec![id_a.pubkey_hex().to_string()], // Bob tracks Alice
            ExtensionFsConfig::default(),
            Arc::clone(&blobs),
            Arc::new(Keystore::open(state_b.path()).unwrap()),
            Arc::new(ContractRegistry::new()),
            Arc::new(ListingStore::new()),
        );

        // Precondition: Bob's root readdir has his own folder + Alice's folder, no listings.
        let before = fs_bob.readdir(Path::new("/")).unwrap();
        let before_names: std::collections::HashSet<&str> =
            before.iter().map(|e| e.name.as_str()).collect();
        assert!(before_names.contains(id_b.pubkey_hex()));
        assert!(before_names.contains(id_a.pubkey_hex()));

        // Alice drops → publishes her manifest.
        let own_a = id_a.pubkey_hex().to_string();
        let p = format!("/{own_a}/{PAID_TRANSFER_DIR}/9REV-public.doc");
        let path = Path::new(&p);
        let fh = fs_alice.create(path, 0o644, 0).unwrap();
        fs_alice.write(path, 0, b"shared bytes", fh).unwrap();
        fs_alice.release(path, fh).unwrap();
        let id = fs_alice.listings.ids().into_iter().next().unwrap();

        // Bob now sees the listing uuid at root.
        let after = fs_bob.readdir(Path::new("/")).unwrap();
        let names: Vec<String> = after.iter().map(|e| e.name.clone()).collect();
        assert!(names.contains(&id));

        // And Bob's getattr on it resolves (dir, from peer manifest).
        let attr = fs_bob.getattr(Path::new(&format!("/{id}"))).unwrap();
        assert_eq!(attr.kind, FileKind::Directory);

        // Alice rmdirs it → her manifest shrinks → Bob stops seeing it.
        fs_alice.rmdir(Path::new(&format!("/{id}"))).unwrap();
        let after_rmdir = fs_bob.readdir(Path::new("/")).unwrap();
        let names_after: Vec<String> = after_rmdir.iter().map(|e| e.name.clone()).collect();
        assert!(!names_after.contains(&id));

        std::mem::forget(state_a);
        std::mem::forget(state_b);
    }

    #[test]
    fn untracked_peer_listings_hidden() {
        // Same two-daemon shape, but Bob does NOT track Alice.
        // Alice's listings must not leak into Bob's readdir /.
        let state_a = tempfile::tempdir().unwrap();
        let state_b = tempfile::tempdir().unwrap();
        let id_a = Arc::new(Identity::load_or_create(state_a.path()).unwrap());
        let id_b = Arc::new(Identity::load_or_create(state_b.path()).unwrap());
        let blobs: Arc<dyn BlobStore> = Arc::new(crate::blob_store::InMemoryBlobStore::new());

        let fs_alice = ExtensionFs::with_registry(
            Arc::clone(&id_a),
            vec![],
            ExtensionFsConfig::default(),
            Arc::clone(&blobs),
            Arc::new(Keystore::open(state_a.path()).unwrap()),
            Arc::new(ContractRegistry::new()),
            Arc::new(ListingStore::new()),
        );
        let fs_bob = ExtensionFs::with_registry(
            Arc::clone(&id_b),
            vec![], // Bob doesn't track Alice
            ExtensionFsConfig::default(),
            Arc::clone(&blobs),
            Arc::new(Keystore::open(state_b.path()).unwrap()),
            Arc::new(ContractRegistry::new()),
            Arc::new(ListingStore::new()),
        );

        let own_a = id_a.pubkey_hex().to_string();
        let p = format!("/{own_a}/{PAID_TRANSFER_DIR}/1REV-untracked.txt");
        let path = Path::new(&p);
        let fh = fs_alice.create(path, 0o644, 0).unwrap();
        fs_alice.write(path, 0, b"x", fh).unwrap();
        fs_alice.release(path, fh).unwrap();
        let id = fs_alice.listings.ids().into_iter().next().unwrap();

        // Bob's readdir doesn't see Alice's listing (she isn't tracked).
        let entries = fs_bob.readdir(Path::new("/")).unwrap();
        let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
        assert!(!names.contains(&id));

        // And getattr on the (untracked) listing is NotFound.
        assert!(matches!(
            fs_bob.getattr(Path::new(&format!("/{id}"))),
            Err(FtFsError::NotFound),
        ));

        std::mem::forget(state_a);
        std::mem::forget(state_b);
    }

    #[test]
    fn manifest_channel_hidden_from_owner_folder_readdir() {
        // The `_manifest` BlobStore channel lives under Alice's
        // prefix, same storage namespace as her regular SELF
        // envelopes. list_own_entries must skip it so the manifest
        // isn't surfaced as a file in her folder.
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        let p = format!("/{own}/{PAID_TRANSFER_DIR}/2REV-anything.txt");
        let path = Path::new(&p);
        let fh = fs.create(path, 0o644, 0).unwrap();
        fs.write(path, 0, b"body", fh).unwrap();
        fs.release(path, fh).unwrap();

        let entries = fs.readdir(Path::new(&format!("/{own}"))).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(!names.contains(&LISTINGS_MANIFEST_CHANNEL));
    }

    #[test]
    fn listing_folder_readdir_lists_info_file() {
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        let p = format!("/{own}/{PAID_TRANSFER_DIR}/4REV-x.txt");
        let path = Path::new(&p);
        let fh = fs.create(path, 0o644, 0).unwrap();
        fs.write(path, 0, b"body", fh).unwrap();
        fs.release(path, fh).unwrap();

        let id = fs.listings.ids().into_iter().next().unwrap();
        let entries = fs.readdir(Path::new(&format!("/{id}"))).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec![LISTING_INFO_FILE]);
    }

    #[test]
    fn info_file_round_trips_as_json() {
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        let p = format!("/{own}/{PAID_TRANSFER_DIR}/42REV-report.pdf");
        let path = Path::new(&p);
        let fh = fs.create(path, 0o644, 0).unwrap();
        fs.write(path, 0, b"body", fh).unwrap();
        fs.release(path, fh).unwrap();

        let id = fs.listings.ids().into_iter().next().unwrap();
        let info_path = format!("/{id}/{LISTING_INFO_FILE}");

        // Read via open + read, as a client would.
        let fh = fs.open(Path::new(&info_path), 0).unwrap();
        let attr = fs.getattr(Path::new(&info_path)).unwrap();
        assert!(attr.size > 0);
        let bytes = fs
            .read(Path::new(&info_path), 0, attr.size as usize, fh)
            .unwrap();
        let listing: Listing = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(listing.owner_pubkey_hex, own);
        assert_eq!(listing.template_name, "Paid transfer");
        assert_eq!(
            listing.spec,
            ListingSpec::PaidTransfer {
                price: 42,
                filename: "report.pdf".into(),
            }
        );
    }

    #[test]
    fn info_file_resolves_cross_daemon_via_peer_manifest() {
        // Bob tracks Alice; Alice drops; Bob reads `.info` without
        // ever having K_listing — only the spec is exposed to him.
        let state_a = tempfile::tempdir().unwrap();
        let state_b = tempfile::tempdir().unwrap();
        let id_a = Arc::new(Identity::load_or_create(state_a.path()).unwrap());
        let id_b = Arc::new(Identity::load_or_create(state_b.path()).unwrap());
        let blobs: Arc<dyn BlobStore> = Arc::new(crate::blob_store::InMemoryBlobStore::new());

        let fs_alice = ExtensionFs::with_registry(
            Arc::clone(&id_a),
            vec![],
            ExtensionFsConfig::default(),
            Arc::clone(&blobs),
            Arc::new(Keystore::open(state_a.path()).unwrap()),
            Arc::new(ContractRegistry::new()),
            Arc::new(ListingStore::new()),
        );
        let fs_bob = ExtensionFs::with_registry(
            Arc::clone(&id_b),
            vec![id_a.pubkey_hex().to_string()],
            ExtensionFsConfig::default(),
            Arc::clone(&blobs),
            Arc::new(Keystore::open(state_b.path()).unwrap()),
            Arc::new(ContractRegistry::new()),
            Arc::new(ListingStore::new()),
        );

        let own_a = id_a.pubkey_hex().to_string();
        let p = format!("/{own_a}/{PAID_TRANSFER_DIR}/13REV-brochure.pdf");
        let path = Path::new(&p);
        let fh = fs_alice.create(path, 0o644, 0).unwrap();
        fs_alice.write(path, 0, b"content", fh).unwrap();
        fs_alice.release(path, fh).unwrap();

        let id = fs_alice.listings.ids().into_iter().next().unwrap();
        let info_path = format!("/{id}/{LISTING_INFO_FILE}");

        let fh = fs_bob.open(Path::new(&info_path), 0).unwrap();
        let attr = fs_bob.getattr(Path::new(&info_path)).unwrap();
        let bytes = fs_bob
            .read(Path::new(&info_path), 0, attr.size as usize, fh)
            .unwrap();
        let listing: Listing = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(listing.owner_pubkey_hex, own_a);
        assert_eq!(
            listing.spec,
            ListingSpec::PaidTransfer {
                price: 13,
                filename: "brochure.pdf".into(),
            }
        );

        std::mem::forget(state_a);
        std::mem::forget(state_b);
    }

    #[test]
    fn token_drop_onto_listing_returns_not_supported() {
        // The ADR-0002 purchase path hits the daemon as a rename
        // from `.tokens/<bill>` to `<listing>/<name>`. Slice 11
        // doesn't execute it; it surfaces NotSupported so the
        // kernel + userspace clients see a clear error pointing
        // at the pending factory work (slice 12+).
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        // Set up a listing so the destination resolves.
        let p = format!("/{own}/{PAID_TRANSFER_DIR}/5REV-x.txt");
        let path = Path::new(&p);
        let fh = fs.create(path, 0o644, 0).unwrap();
        fs.write(path, 0, b"", fh).unwrap();
        fs.release(path, fh).unwrap();
        let id = fs.listings.ids().into_iter().next().unwrap();

        // Pretend to drag a `.token` into the listing. The token
        // file doesn't actually need to exist — the shape check
        // alone triggers the stub.
        let token_src = format!("/{own}/{TOKENS_DIR}/100-REV.0.token");
        let dest = format!("/{id}/payment");
        assert!(matches!(
            fs.rename(Path::new(&token_src), Path::new(&dest)),
            Err(FtFsError::NotSupported),
        ));
    }

    #[test]
    fn editing_own_file_replaces_old_blob_not_duplicates() {
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        let p = format!("/{own}/notes.txt");
        let path = Path::new(&p);

        // First write.
        let fh = fs.create(path, 0o644, 0).unwrap();
        fs.write(path, 0, b"version one", fh).unwrap();
        fs.release(path, fh).unwrap();

        // Open, read (populates read cache), edit via write without
        // a prior create (lazy-promote path), release.
        let fh = fs.open(path, 0).unwrap();
        let _ = fs.read(path, 0, 100, fh).unwrap();
        fs.write(path, 0, b"version two", fh).unwrap();
        fs.release(path, fh).unwrap();

        // Readdir should show the file exactly once with the new content.
        let entries = fs.readdir(Path::new(&format!("/{own}"))).unwrap();
        let hits: Vec<&str> = entries
            .iter()
            .map(|e| e.name.as_str())
            .filter(|n| *n == "notes.txt")
            .collect();
        assert_eq!(hits.len(), 1, "edit must not duplicate the blob");

        let fh = fs.open(path, 0).unwrap();
        assert_eq!(fs.read(path, 0, 100, fh).unwrap(), b"version two");

        // BlobStore sanity: exactly one blob under own prefix.
        // (plus the manifest + no listings, so expect 2 channels)
        let channels = fs.blobs.list(&own).unwrap();
        let non_manifest: Vec<_> = channels
            .iter()
            .filter(|c| c.as_str() != LISTINGS_MANIFEST_CHANNEL)
            .collect();
        assert_eq!(non_manifest.len(), 1);
    }

    #[test]
    fn recipient_editing_a_recv_blob_doesnt_leave_the_old_recv_behind() {
        // Alice transfers a file to Bob via SELF→RECV. Bob then
        // edits it and releases. The old RECV blob should be
        // replaced, not duplicated — regression guard against the
        // slice-11 behavior where edits always minted a fresh SELF
        // without removing the prior entry.
        let state_a = tempfile::tempdir().unwrap();
        let state_b = tempfile::tempdir().unwrap();
        let id_a = Arc::new(Identity::load_or_create(state_a.path()).unwrap());
        let id_b = Arc::new(Identity::load_or_create(state_b.path()).unwrap());
        let blobs: Arc<dyn BlobStore> = Arc::new(crate::blob_store::InMemoryBlobStore::new());

        let fs_a = ExtensionFs::new(
            Arc::clone(&id_a),
            vec![],
            ExtensionFsConfig::default(),
            Arc::clone(&blobs),
            Arc::new(Keystore::open(state_a.path()).unwrap()),
        );
        let fs_b = ExtensionFs::new(
            Arc::clone(&id_b),
            vec![],
            ExtensionFsConfig::default(),
            Arc::clone(&blobs),
            Arc::new(Keystore::open(state_b.path()).unwrap()),
        );

        let own_a = id_a.pubkey_hex().to_string();
        let own_b = id_b.pubkey_hex().to_string();

        // Alice creates + transfers.
        let src = format!("/{own_a}/payload.txt");
        let fh = fs_a.create(Path::new(&src), 0o644, 0).unwrap();
        fs_a.write(Path::new(&src), 0, b"from alice", fh).unwrap();
        fs_a.release(Path::new(&src), fh).unwrap();
        let dst = format!("/{own_b}/received.txt");
        fs_a.rename(Path::new(&src), Path::new(&dst)).unwrap();

        // Bob sees exactly one blob under his prefix.
        assert_eq!(fs_b.blobs.list(&own_b).unwrap().len(), 1);

        // Bob opens, reads, edits, releases.
        let bob_path = format!("/{own_b}/received.txt");
        let fh = fs_b.open(Path::new(&bob_path), 0).unwrap();
        let _ = fs_b.read(Path::new(&bob_path), 0, 100, fh).unwrap();
        fs_b.write(Path::new(&bob_path), 0, b"edited by bob", fh)
            .unwrap();
        fs_b.release(Path::new(&bob_path), fh).unwrap();

        // Still exactly one blob under Bob's prefix (the old RECV
        // was replaced, not stacked).
        assert_eq!(fs_b.blobs.list(&own_b).unwrap().len(), 1);

        // Bob reads back the new content; readdir doesn't duplicate.
        let fh = fs_b.open(Path::new(&bob_path), 0).unwrap();
        assert_eq!(
            fs_b.read(Path::new(&bob_path), 0, 100, fh).unwrap(),
            b"edited by bob"
        );
        let entries = fs_b.readdir(Path::new(&format!("/{own_b}"))).unwrap();
        let hits: Vec<&str> = entries
            .iter()
            .map(|e| e.name.as_str())
            .filter(|n| *n == "received.txt")
            .collect();
        assert_eq!(hits.len(), 1);

        std::mem::forget(state_a);
        std::mem::forget(state_b);
    }

    #[test]
    fn recv_rename_within_own_folder_promotes_to_self() {
        // Alice → Bob transfer, then Bob renames the file within
        // his own folder. The underlying blob flips RECV→SELF with
        // a fresh K; content survives; readdir surfaces the new
        // name, not the old.
        let state_a = tempfile::tempdir().unwrap();
        let state_b = tempfile::tempdir().unwrap();
        let id_a = Arc::new(Identity::load_or_create(state_a.path()).unwrap());
        let id_b = Arc::new(Identity::load_or_create(state_b.path()).unwrap());
        let blobs: Arc<dyn BlobStore> = Arc::new(crate::blob_store::InMemoryBlobStore::new());

        let fs_a = ExtensionFs::new(
            Arc::clone(&id_a),
            vec![],
            ExtensionFsConfig::default(),
            Arc::clone(&blobs),
            Arc::new(Keystore::open(state_a.path()).unwrap()),
        );
        let fs_b = ExtensionFs::new(
            Arc::clone(&id_b),
            vec![],
            ExtensionFsConfig::default(),
            Arc::clone(&blobs),
            Arc::new(Keystore::open(state_b.path()).unwrap()),
        );

        let own_a = id_a.pubkey_hex().to_string();
        let own_b = id_b.pubkey_hex().to_string();

        // Alice creates + transfers → Bob has a RECV at /<own_b>/received.txt.
        let src = format!("/{own_a}/gift.txt");
        let fh = fs_a.create(Path::new(&src), 0o644, 0).unwrap();
        fs_a.write(Path::new(&src), 0, b"content X", fh).unwrap();
        fs_a.release(Path::new(&src), fh).unwrap();
        let dst = format!("/{own_b}/received.txt");
        fs_a.rename(Path::new(&src), Path::new(&dst)).unwrap();

        // Bob renames WITHIN his own folder — RECV→SELF.
        let bob_old = format!("/{own_b}/received.txt");
        let bob_new = format!("/{own_b}/kept.txt");
        fs_b.rename(Path::new(&bob_old), Path::new(&bob_new))
            .unwrap();

        // Readdir shows the new name only; still exactly one blob.
        let entries = fs_b.readdir(Path::new(&format!("/{own_b}"))).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"kept.txt"));
        assert!(!names.contains(&"received.txt"));
        assert_eq!(fs_b.blobs.list(&own_b).unwrap().len(), 1);

        // Content survives.
        let fh = fs_b.open(Path::new(&bob_new), 0).unwrap();
        assert_eq!(
            fs_b.read(Path::new(&bob_new), 0, 100, fh).unwrap(),
            b"content X"
        );

        // The remaining blob is now SELF (ownership transferred).
        let channel = fs_b.find_own_channel("kept.txt").unwrap();
        let blob = fs_b.blobs.get(&own_b, &channel).unwrap().unwrap();
        assert_eq!(&blob[..4], b"SELF");

        std::mem::forget(state_a);
        std::mem::forget(state_b);
    }

    #[test]
    fn recv_rename_cross_folder_forwards_to_third_party() {
        // Alice → Bob transfer. Bob then forwards the file to
        // Charlie by renaming his received blob into Charlie's
        // pubkey folder. Charlie decrypts the new RECV with his
        // own private key; Bob no longer has it.
        let state_a = tempfile::tempdir().unwrap();
        let state_b = tempfile::tempdir().unwrap();
        let state_c = tempfile::tempdir().unwrap();
        let id_a = Arc::new(Identity::load_or_create(state_a.path()).unwrap());
        let id_b = Arc::new(Identity::load_or_create(state_b.path()).unwrap());
        let id_c = Arc::new(Identity::load_or_create(state_c.path()).unwrap());
        let blobs: Arc<dyn BlobStore> = Arc::new(crate::blob_store::InMemoryBlobStore::new());

        let fs_a = ExtensionFs::new(
            Arc::clone(&id_a),
            vec![],
            ExtensionFsConfig::default(),
            Arc::clone(&blobs),
            Arc::new(Keystore::open(state_a.path()).unwrap()),
        );
        let fs_b = ExtensionFs::new(
            Arc::clone(&id_b),
            vec![],
            ExtensionFsConfig::default(),
            Arc::clone(&blobs),
            Arc::new(Keystore::open(state_b.path()).unwrap()),
        );
        let fs_c = ExtensionFs::new(
            Arc::clone(&id_c),
            vec![],
            ExtensionFsConfig::default(),
            Arc::clone(&blobs),
            Arc::new(Keystore::open(state_c.path()).unwrap()),
        );

        let own_a = id_a.pubkey_hex().to_string();
        let own_b = id_b.pubkey_hex().to_string();
        let own_c = id_c.pubkey_hex().to_string();

        // Alice → Bob.
        let src = format!("/{own_a}/leak.txt");
        let fh = fs_a.create(Path::new(&src), 0o644, 0).unwrap();
        fs_a.write(Path::new(&src), 0, b"forwarded content", fh)
            .unwrap();
        fs_a.release(Path::new(&src), fh).unwrap();
        let to_bob = format!("/{own_b}/leak.txt");
        fs_a.rename(Path::new(&src), Path::new(&to_bob)).unwrap();

        // Bob → Charlie (forward).
        let to_charlie = format!("/{own_c}/leak.txt");
        fs_b.rename(Path::new(&to_bob), Path::new(&to_charlie))
            .unwrap();

        // Bob no longer has the file.
        let b_entries = fs_b.readdir(Path::new(&format!("/{own_b}"))).unwrap();
        let b_names: Vec<&str> = b_entries.iter().map(|e| e.name.as_str()).collect();
        assert!(!b_names.contains(&"leak.txt"));

        // Charlie can read it.
        let c_entries = fs_c.readdir(Path::new(&format!("/{own_c}"))).unwrap();
        let c_names: Vec<&str> = c_entries.iter().map(|e| e.name.as_str()).collect();
        assert!(c_names.contains(&"leak.txt"));
        let fh = fs_c.open(Path::new(&to_charlie), 0).unwrap();
        assert_eq!(
            fs_c.read(Path::new(&to_charlie), 0, 100, fh).unwrap(),
            b"forwarded content"
        );

        std::mem::forget(state_a);
        std::mem::forget(state_b);
        std::mem::forget(state_c);
    }

    #[test]
    fn disk_backed_listing_survives_daemon_restart() {
        // State dir + blob store persist across both "runs"; each
        // run builds a fresh ExtensionFs on top. The on-chain blob
        // + the on-disk listing manifest together must suffice to
        // re-expose the uuid folder after restart.
        let state = tempfile::tempdir().unwrap();
        let identity = Arc::new(Identity::load_or_create(state.path()).unwrap());
        let blobs: Arc<dyn BlobStore> = Arc::new(crate::blob_store::InMemoryBlobStore::new());

        // Run 1: Alice drops a file, we grab the listing id, then
        // the ExtensionFs is dropped (simulating daemon exit).
        let id = {
            let keystore = Arc::new(Keystore::open(state.path()).unwrap());
            let listings = Arc::new(ListingStore::open(state.path()).unwrap());
            let fs = ExtensionFs::with_registry(
                Arc::clone(&identity),
                vec![],
                ExtensionFsConfig::default(),
                Arc::clone(&blobs),
                keystore,
                Arc::new(ContractRegistry::new()),
                listings,
            );
            let own = identity.pubkey_hex().to_string();
            let p = format!("/{own}/{PAID_TRANSFER_DIR}/4REV-across-restart.txt");
            let path = Path::new(&p);
            let fh = fs.create(path, 0o644, 0).unwrap();
            fs.write(path, 0, b"survive me", fh).unwrap();
            fs.release(path, fh).unwrap();
            fs.listings.ids().into_iter().next().unwrap()
        };

        // Run 2: fresh ExtensionFs reads the state_dir — the uuid
        // folder is still there at root, with the right spec.
        let fs2 = {
            let keystore = Arc::new(Keystore::open(state.path()).unwrap());
            let listings = Arc::new(ListingStore::open(state.path()).unwrap());
            ExtensionFs::with_registry(
                Arc::clone(&identity),
                vec![],
                ExtensionFsConfig::default(),
                Arc::clone(&blobs),
                keystore,
                Arc::new(ContractRegistry::new()),
                listings,
            )
        };

        // Root readdir still surfaces the listing.
        let entries = fs2.readdir(Path::new("/")).unwrap();
        let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
        assert!(names.contains(&id));

        // Spec round-tripped.
        let listing = fs2.listings.get(&id).unwrap();
        assert_eq!(
            listing.spec,
            ListingSpec::PaidTransfer {
                price: 4,
                filename: "across-restart.txt".into(),
            }
        );

        // And the owner can still rmdir it after restart.
        fs2.rmdir(Path::new(&format!("/{id}"))).unwrap();
        assert!(fs2.listings.get(&id).is_none());

        std::mem::forget(state);
    }

    #[test]
    fn create_write_release_round_trip_through_fuse_ops() {
        // The whole encrypted-write path exercised through the
        // trait methods. On release the plaintext should round-trip
        // back out via open+read.
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        let p = format!("/{own}/notes.txt");
        let path = Path::new(&p);
        let fh = fs.create(path, 0o644, 0).unwrap();
        assert_eq!(fs.write(path, 0, b"hello", fh).unwrap(), 5);
        assert_eq!(fs.write(path, 5, b", world", fh).unwrap(), 7);
        fs.release(path, fh).unwrap();

        // Reopen and read.
        let fh2 = fs.open(path, 0).unwrap();
        assert_eq!(fs.read(path, 0, 1024, fh2).unwrap(), b"hello, world");
        assert_eq!(fs.read(path, 7, 5, fh2).unwrap(), b"world");
        fs.release(path, fh2).unwrap();
    }

    #[test]
    fn readdir_lists_written_file_with_plaintext_name() {
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        let p = format!("/{own}/secret.md");
        let path = Path::new(&p);
        let fh = fs.create(path, 0o644, 0).unwrap();
        fs.write(path, 0, b"# hi", fh).unwrap();
        fs.release(path, fh).unwrap();

        let entries = fs.readdir(Path::new(&format!("/{own}"))).unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"secret.md"));
        assert!(names.contains(&TOKENS_DIR));
        assert!(names.contains(&PAID_TRANSFER_DIR));
    }

    #[test]
    fn write_outside_own_folder_is_denied() {
        let foreign = format!("04{}", "ab".repeat(64));
        let fs = make_fs(vec![foreign.clone()]);
        let p = format!("/{foreign}/sneak.txt");
        assert!(matches!(
            fs.create(Path::new(&p), 0o644, 0),
            Err(FtFsError::PermissionDenied),
        ));
    }

    #[test]
    fn read_without_prior_open_returns_not_found() {
        // open() populates the read cache; a bare read() without
        // open shouldn't find anything.
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        let p = format!("/{own}/never-opened");
        assert!(matches!(
            fs.read(Path::new(&p), 0, 10, 0),
            Err(FtFsError::NotFound),
        ));
    }

    #[test]
    fn truncate_then_write_shortens_file() {
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        let p = format!("/{own}/short.txt");
        let path = Path::new(&p);
        let fh = fs.create(path, 0o644, 0).unwrap();
        fs.write(path, 0, b"this is a long sentence", fh).unwrap();
        fs.truncate(path, 7).unwrap();
        fs.release(path, fh).unwrap();

        let fh2 = fs.open(path, 0).unwrap();
        assert_eq!(fs.read(path, 0, 100, fh2).unwrap(), b"this is");
    }

    #[test]
    fn two_files_round_trip_independently() {
        let fs = make_fs(vec![]);
        let own = fs.own_pubkey().to_string();
        let pa = format!("/{own}/a.txt");
        let pb = format!("/{own}/b.txt");
        let fh_a = fs.create(Path::new(&pa), 0o644, 0).unwrap();
        fs.write(Path::new(&pa), 0, b"aaa", fh_a).unwrap();
        fs.release(Path::new(&pa), fh_a).unwrap();
        let fh_b = fs.create(Path::new(&pb), 0o644, 0).unwrap();
        fs.write(Path::new(&pb), 0, b"bbbbbb", fh_b).unwrap();
        fs.release(Path::new(&pb), fh_b).unwrap();

        let fh_a2 = fs.open(Path::new(&pa), 0).unwrap();
        assert_eq!(fs.read(Path::new(&pa), 0, 100, fh_a2).unwrap(), b"aaa");
        let fh_b2 = fs.open(Path::new(&pb), 0).unwrap();
        assert_eq!(fs.read(Path::new(&pb), 0, 100, fh_b2).unwrap(), b"bbbbbb");
    }

    #[test]
    fn tracked_list_dedupes_and_drops_self() {
        let tmp = tempfile::tempdir().unwrap();
        let identity = Arc::new(Identity::load_or_create(tmp.path()).unwrap());
        let own = identity.pubkey_hex().to_string();
        let other = format!("04{}", "cd".repeat(64));
        let blobs: Arc<dyn BlobStore> = Arc::new(crate::blob_store::InMemoryBlobStore::new());
        let keystore = Arc::new(Keystore::open(tmp.path()).unwrap());
        let fs = ExtensionFs::new(
            Arc::clone(&identity),
            vec![
                own.clone(),          // dropped: that's us
                other.clone(),        //
                other.clone(),        // dedup
                other.to_uppercase(), // case-fold dedup
            ],
            ExtensionFsConfig::default(),
            blobs,
            keystore,
        );
        assert_eq!(fs.tracked, vec![other]);
    }
}
