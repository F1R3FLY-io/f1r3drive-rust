//! Registry URN of the on-chain `Fs` agent.
//!
//! Published at genesis by
//! `f1r3node-rust/casper/src/rust/genesis/contracts/fs_genesis.rs` and
//! referenced by every canonical client example (see
//! `rholang/examples/fileio_static.rho:31`).

/// Fixed URN of the global `Fs` agent instance. All client Rholang looks it
/// up via `rho:registry:lookup`.
pub const FS_AGENT_URN: &str = "rho:id:zphjgsfy13h1k85isc8rtwtgt3t9zzt5pjd5ihykfmyapfc4wt3x5h";
