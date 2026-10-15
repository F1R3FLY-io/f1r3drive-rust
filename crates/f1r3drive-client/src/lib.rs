//! gRPC client, deploy signing, and secp256k1 key loading.
//!
//! Exposes:
//! - [`KeyPair`] — load a 32-byte secp256k1 private key from hex, raw bytes,
//!   or a file.
//! - [`DeployToSign`] — build and sign a `DeployDataProto` so the receiving
//!   f1r3node accepts it via `DeployService.doDeploy`.
//! - [`NodeClient`] — thin async wrapper over the generated tonic clients
//!   with just the four verbs FUSE needs: `exploratory_deploy`, `do_deploy`,
//!   `propose`, `is_finalized`.

pub mod client;
pub mod error;
pub mod key;
pub mod sign;

pub use client::{DeployAck, ExploratoryResult, NodeClient, ProposeAck, StatusInfo};
pub use error::ClientError;
pub use key::KeyPair;
pub use sign::DeployToSign;
