//! Rholang snippet generation + reply decoding targeting the on-chain
//! `Fs` agent published by `f1r3node-rust`.
//!
//! See the plan file for the full stage breakdown. Stage 2 (this crate)
//! produces deterministic Rholang programs for each FUSE verb and decodes
//! the `[true, ...] | [false, code, msg]` replies they leave on the
//! deploy's return channel.

pub mod error_codes;
pub mod record;
pub mod reply;
pub mod snippet;
pub mod urn;
pub mod vault;

pub use error_codes::*;
pub use record::{par_as_list, par_as_map, par_as_stat_record, StatRecord};
pub use reply::{
    decode_reply, par_as_bool, par_as_bytes, par_as_int, par_as_string, DecodeError, FsError,
    FsReply,
};
pub use snippet::{Snippet, SnippetBuilder};
pub use urn::FS_AGENT_URN;
pub use vault::{check_balance_snippet, decode_balance_reply, transfer_snippet, BalanceError};
