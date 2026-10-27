//! Contract-folder registry — the ADR-0002 plug-in surface that lets
//! the daemon render per-template subfolders inside every pubkey
//! folder and treat drops into them as triggers for templated
//! deploys.
//!
//! Slice 7 scope: client-side plumbing only. A trait, a registry,
//! and the Paid-transfer template. The actual on-chain Rholang
//! factory that materialises purchases + REV transfers lands with
//! slice 8; this slice stops at "the daemon can parse a drop,
//! mint a listing, and expose it at root readdir."
//!
//! Shape:
//!
//! ```text
//! /<my-pubkey>/
//!   ├── Paid transfer/         fixed-name template subfolder
//!   │   └── (drop file here)   → create+write+release triggers
//!   │                            ListingStore::mint for the parsed spec
//!   └── ...
//! /<uuid-listing>/              appears at root as the result of a mint
//! ```

use serde::{Deserialize, Serialize};

use crate::extension_fs::PUBKEY_HEX_LEN;

/// One leaf file in a folder-shaped listing's public tree manifest.
/// Serialized inside `.info` so prospective buyers can inspect the
/// shape (what files, what sizes) before dropping a token. The
/// envelope's encrypted bytes aren't exposed pre-purchase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TreeEntry {
    /// Slash-joined rel-path from the listing's root folder.
    pub rel_path: String,
    /// Plaintext byte size of the leaf (not the ciphertext size).
    pub size: u64,
}

/// The parsed intent extracted from a filename dropped into a
/// contract-template folder. Slice 7 modeled paid transfer for single
/// files; the `tree` field (added for listing-as-folder) is populated
/// only when the listing was minted by renaming a folder into
/// `Paid transfer/` — single-file listings keep `tree = None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ListingSpec {
    /// `<N>REV-<rest>` — Alice is listing a payload for N atomic REV
    /// units, with `<rest>` as the on-sale name exposed to buyers.
    /// For single-file listings, `<rest>` is the plaintext filename
    /// and `tree` is `None`. For folder listings, `<rest>` is the
    /// top-level folder name and `tree` is a flat vec of every leaf
    /// inside.
    PaidTransfer {
        price: u64,
        filename: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tree: Option<Vec<TreeEntry>>,
    },
}

/// A client-side contract-folder template. The trait is small on
/// purpose: slice 7 only needs filename parsing. Slice 8 extends
/// with a factory method that returns a Rholang deploy pipeline.
pub trait ContractTemplate: Send + Sync {
    /// The folder name as it appears under every pubkey folder. The
    /// daemon enforces at `ExtPath::parse` time that this slot is
    /// reserved — users can't shadow it with a regular file.
    fn name(&self) -> &'static str;

    /// Parse the dropped filename into a listing spec. `None` means
    /// the drop is malformed for this template; the daemon rejects
    /// the create with `InvalidArgument`.
    fn parse(&self, filename: &str) -> Option<ListingSpec>;
}

/// The one v1 template. The surface is a filename like
/// `10REV-notes.txt` → `ListingSpec::PaidTransfer { price: 10, filename: "notes.txt" }`.
pub struct PaidTransferTemplate;

impl ContractTemplate for PaidTransferTemplate {
    fn name(&self) -> &'static str {
        "Paid transfer"
    }

    fn parse(&self, filename: &str) -> Option<ListingSpec> {
        // Shape: `<decimal>REV-<rest>`. `rsplit_once` + a REV suffix
        // check keeps the parser forgiving — filenames containing
        // dashes are fine, we only split at the first `-`.
        let (prefix, rest) = filename.split_once('-')?;
        let n_str = prefix.strip_suffix("REV")?;
        if rest.is_empty() {
            return None;
        }
        let price: u64 = n_str.parse().ok()?;
        Some(ListingSpec::PaidTransfer {
            price,
            filename: rest.to_string(),
            tree: None,
        })
    }
}

/// Daemon-side registry. The lookup is by template name so
/// `ExtPath::parse` + the drop handlers can go directly from
/// `OwnContractTemplateDir(name)` to its template without reflecting
/// over the full set.
pub struct ContractRegistry {
    templates: Vec<Box<dyn ContractTemplate>>,
}

impl Default for ContractRegistry {
    fn default() -> Self {
        Self {
            templates: vec![Box::new(PaidTransferTemplate)],
        }
    }
}

impl ContractRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Find a template by its subfolder name. Returns `None` if the
    /// name isn't registered; the daemon treats that as a user
    /// typo-ed path.
    pub fn find(&self, name: &str) -> Option<&dyn ContractTemplate> {
        self.templates
            .iter()
            .find(|t| t.name() == name)
            .map(|t| t.as_ref())
    }

    /// All registered template names, in registration order. Used by
    /// readdir on an owner's folder to render each template as a
    /// subdirectory entry.
    pub fn names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.templates.iter().map(|t| t.name())
    }
}

/// Opaque 32-char hex ID for a listing. The daemon uses this as the
/// top-level folder name under `/`, so `/<id>` becomes the public
/// address of Alice's listing.
pub fn mint_listing_id() -> String {
    use rand::{rngs::OsRng, TryRngCore};
    let mut bytes = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .expect("OS CSPRNG required for listing id");
    hex::encode(bytes)
}

/// Validate that a string looks like a listing id (32 lowercase hex
/// chars). Used by `ExtPath::parse` to tell listing folders apart
/// from pubkey folders at the root level.
pub fn is_listing_id(s: &str) -> bool {
    // Pubkey folders are 130 chars; listing ids are 32 chars. The
    // length disjointedness is intentional — no need for a tag byte.
    s.len() == 32
        && s.chars().all(|c| c.is_ascii_hexdigit())
        && s == s.to_lowercase()
        && s.len() != PUBKEY_HEX_LEN
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paid_transfer_parses_basic_shape() {
        let t = PaidTransferTemplate;
        assert_eq!(
            t.parse("10REV-notes.txt"),
            Some(ListingSpec::PaidTransfer {
                price: 10,
                filename: "notes.txt".into(),
                tree: None,
            })
        );
    }

    #[test]
    fn paid_transfer_accepts_filenames_with_dashes() {
        let t = PaidTransferTemplate;
        // Only the first `-` separates price from filename.
        assert_eq!(
            t.parse("5REV-my-notes-2.txt"),
            Some(ListingSpec::PaidTransfer {
                price: 5,
                filename: "my-notes-2.txt".into(),
                tree: None,
            })
        );
    }

    #[test]
    fn paid_transfer_requires_rev_suffix() {
        let t = PaidTransferTemplate;
        assert_eq!(t.parse("10USD-notes.txt"), None);
    }

    #[test]
    fn paid_transfer_requires_nonempty_filename() {
        let t = PaidTransferTemplate;
        assert_eq!(t.parse("10REV-"), None);
    }

    #[test]
    fn paid_transfer_rejects_missing_dash() {
        let t = PaidTransferTemplate;
        assert_eq!(t.parse("10REVnotes.txt"), None);
    }

    #[test]
    fn paid_transfer_rejects_non_numeric_price() {
        let t = PaidTransferTemplate;
        assert_eq!(t.parse("tenREV-notes.txt"), None);
    }

    #[test]
    fn registry_default_has_paid_transfer() {
        let r = ContractRegistry::new();
        assert!(r.find("Paid transfer").is_some());
        let names: Vec<&str> = r.names().collect();
        assert_eq!(names, vec!["Paid transfer"]);
    }

    #[test]
    fn registry_rejects_unknown_name() {
        let r = ContractRegistry::new();
        assert!(r.find("Rent-a-cat").is_none());
    }

    #[test]
    fn minted_ids_are_32_hex_chars() {
        let id = mint_listing_id();
        assert_eq!(id.len(), 32);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(id, id.to_lowercase());
    }

    #[test]
    fn minted_ids_differ_across_calls() {
        let a = mint_listing_id();
        let b = mint_listing_id();
        // 128-bit collision probability — never a flake.
        assert_ne!(a, b);
    }

    #[test]
    fn is_listing_id_rejects_pubkey_shape() {
        // 130-char hex strings are pubkeys, not listings.
        let pubkey = "04".to_string() + &"ab".repeat(64);
        assert!(!is_listing_id(&pubkey));
    }

    #[test]
    fn is_listing_id_rejects_uppercase() {
        assert!(!is_listing_id("AB".repeat(16).as_str()));
    }
}
