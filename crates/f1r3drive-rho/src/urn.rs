//! Registry URN of the on-chain `Fs` agent.
//!
//! Published at genesis by
//! `f1r3node-rust/casper/src/rust/genesis/contracts/fs_genesis.rs` via
//! `fs_genesis_uri(&FS_GENERATOR_PUB_KEY)`. The hex value below was
//! computed by invoking that function against the hard-coded
//! `FS_GENERATOR_PK` in
//! `casper/src/rust/genesis/contracts/standard_deploys.rs:94` and
//! verified against a running v0.4.46 standalone node (the reply
//! shape matches `Fs.openFile` returning `[false, FSERR_UNSUPPORTED,
//! …]` for a nonexistent bundle name).

/// Fixed URN of the global `Fs` agent instance. All client Rholang
/// looks it up via `rho:registry:lookup`.
pub const FS_AGENT_URN: &str = "rho:id:naz9dp5st6droro6dm7f3ehe5rh1s6hbs9pj8wnxpx1ckr89xthw3e";
