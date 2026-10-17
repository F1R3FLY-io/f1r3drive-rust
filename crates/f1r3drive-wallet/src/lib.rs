//! Wallet domain for f1r3drive-rust.
//!
//! Pure data + functions. No gRPC, no FUSE, no I/O — this crate is
//! deliberately kept dependency-light so Stage 1 can land before any
//! Stage 2+ on-chain plumbing exists. The next stage (balance cache)
//! will depend on this crate; the FUSE overlay (Stage 3) will
//! consume it through a cache wrapper.
//!
//! Three modules:
//! - [`address`] — `RevAddress` and derivation from a secp256k1
//!   public key (matches `rholang/.../util/VaultAddress` on
//!   f1r3node-rust).
//! - [`denomination`] — the 19 fixed `.token` denominations and the
//!   greedy decomposition the Finder-ext `CHANGE` action depends on.
//! - [`wallet`] — `WalletState` + in-memory `WalletRegistry`.
//!
//! See `docs/architecture/ADR-0001-token-as-file.md` for how these
//! fit into the overall tokens-as-files design.

pub mod address;
pub mod base58;
pub mod cache;
pub mod denomination;
pub mod wallet;

pub use address::{AddressError, RevAddress};
pub use cache::{BalanceCache, Entry, FetchError, DEFAULT_TTL};
pub use denomination::{decompose, total, DenomBill, DENOMINATIONS};
pub use wallet::{LockState, WalletRegistry, WalletState};
