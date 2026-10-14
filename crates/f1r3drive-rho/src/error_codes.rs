//! `FSERR_*` codes returned on the Rholang wire by `Fs`, `File`, and `Dir`.
//!
//! Mirrors `f1r3node-rust/rholang/src/rust/interpreter/io/errors.rs`. Codes
//! are consensus-observable — DO NOT rename or reorder.

/// Permission denied; a mutator was called on a read-only file / dir, or on
/// a `Fs` instance that has been revoked.
pub const FSERR_PERM: &str = "FSERR_PERM";

/// Target path not present.
pub const FSERR_NOT_FOUND: &str = "FSERR_NOT_FOUND";

/// Caller passed a bad argument (wrong type, out-of-range int, etc.).
pub const FSERR_BAD_ARG: &str = "FSERR_BAD_ARG";

/// Unsupported operation: unknown method, consensus-mode `chown`, etc.
pub const FSERR_UNSUPPORTED: &str = "FSERR_UNSUPPORTED";

/// Generic I/O failure from the native handler.
pub const FSERR_IO: &str = "FSERR_IO";

/// Resource is busy — typically a locked range.
pub const FSERR_BUSY: &str = "FSERR_BUSY";

/// Operation was cancelled (deploy-boundary cleanup).
pub const FSERR_CANCELLED: &str = "FSERR_CANCELLED";

/// Caller tried to use a closed fd.
pub const FSERR_CLOSED: &str = "FSERR_CLOSED";

/// Leader and follower reached different states.
pub const FSERR_CONSENSUS_DIVERGENCE: &str = "FSERR_CONSENSUS_DIVERGENCE";

/// Attempted a rename or hard-link across devices.
pub const FSERR_CROSS_DEVICE: &str = "FSERR_CROSS_DEVICE";

/// A lock-wait cycle was detected.
pub const FSERR_DEADLOCK: &str = "FSERR_DEADLOCK";

/// Fd quarantined; caller must `close` and retry.
pub const FSERR_QUARANTINE: &str = "FSERR_QUARANTINE";

/// Quota (per-op size cap, concurrent-fd count, etc.) was exceeded.
pub const FSERR_QUOTA_EXCEEDED: &str = "FSERR_QUOTA_EXCEEDED";

/// `Fs` instance was revoked.
pub const FSERR_REVOKED: &str = "FSERR_REVOKED";

/// Target already exists; set on `create_exclusive` and `rename`-into-dir
/// collisions.
pub const FSERR_ALREADY_EXISTS: &str = "FSERR_ALREADY_EXISTS";

/// Set of every known code, for exhaustive matching in tests.
pub const ALL_CODES: &[&str] = &[
    FSERR_PERM,
    FSERR_NOT_FOUND,
    FSERR_BAD_ARG,
    FSERR_UNSUPPORTED,
    FSERR_IO,
    FSERR_BUSY,
    FSERR_CANCELLED,
    FSERR_CLOSED,
    FSERR_CONSENSUS_DIVERGENCE,
    FSERR_CROSS_DEVICE,
    FSERR_DEADLOCK,
    FSERR_QUARANTINE,
    FSERR_QUOTA_EXCEEDED,
    FSERR_REVOKED,
    FSERR_ALREADY_EXISTS,
];
