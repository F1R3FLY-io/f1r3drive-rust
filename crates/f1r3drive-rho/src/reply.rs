//! Decode `[true, ...]`/`[false, code, msg]` replies that FS verbs leave
//! on their `return` channel into typed Rust values.
//!
//! Every snippet produced by [`crate::snippet::SnippetBuilder`] arranges for
//! the Fs/File/Dir agent reply to land as a single `Par` sent on the
//! deploy's canonical return channel. The server surfaces that Par via
//! `ExploratoryDeployResponse.post_block_data: Vec<Par>` (one element in
//! the happy path, zero on an unresponsive deploy).

use f1r3drive_proto::rhoapi::expr::ExprInstance;
use f1r3drive_proto::rhoapi::{EList, ETuple, Expr, Par};

use crate::error_codes::ALL_CODES;

/// A rich-but-opaque reply. For strongly-typed access per verb, call the
/// `expect_*` helpers below.
#[derive(Debug, Clone)]
pub enum FsReply {
    /// `[true, ...]` — the trailing elements carry whatever payload the
    /// verb promised. For verbs that return `[true]` with no payload,
    /// `payload` is empty.
    Ok { payload: Vec<Par> },

    /// `[false, code, msg]` — a canonical FSERR failure.
    Err(FsError),
}

/// A typed error pulled out of a `[false, code, msg]` reply.
#[derive(Debug, Clone, thiserror::Error)]
#[error("{code}: {message}")]
pub struct FsError {
    /// Canonical `"FSERR_*"` identifier. Known values are enumerated in
    /// [`crate::error_codes`].
    pub code: String,
    /// Free-form human-readable detail.
    pub message: String,
}

impl FsError {
    /// Returns `true` if `code` is one of the known `FSERR_*` constants.
    /// Unknown codes are not necessarily wrong — the native layer may have
    /// added one — but useful during development.
    pub fn is_known(&self) -> bool {
        ALL_CODES.iter().any(|c| *c == self.code)
    }
}

/// Error returned by the decoder itself when the reply doesn't match any
/// recognized shape.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("no reply received (deploy produced no data at the return channel)")]
    NoReply,

    #[error("expected a single reply Par, got {0}")]
    TooManyReplies(usize),

    #[error("reply Par has no exprs")]
    EmptyPar,

    #[error("reply Par is not a list or tuple")]
    NotListLike,

    #[error("reply list is empty (expected at least one bool)")]
    EmptyList,

    #[error("first list element is not a bool")]
    NotBool,

    #[error("error reply shape is not [false, string, string]")]
    MalformedError,
}

/// Decode a verb reply from the server's `post_block_data`.
pub fn decode_reply(pars: &[Par]) -> Result<FsReply, DecodeError> {
    match pars.len() {
        0 => Err(DecodeError::NoReply),
        1 => decode_one(&pars[0]),
        n => Err(DecodeError::TooManyReplies(n)),
    }
}

fn decode_one(par: &Par) -> Result<FsReply, DecodeError> {
    let first_expr = par.exprs.first().ok_or(DecodeError::EmptyPar)?;
    let elems = list_elements(first_expr).ok_or(DecodeError::NotListLike)?;

    let (ok_par, rest) = elems.split_first().ok_or(DecodeError::EmptyList)?;
    let is_ok = extract_bool(ok_par).ok_or(DecodeError::NotBool)?;

    if is_ok {
        Ok(FsReply::Ok {
            payload: rest.to_vec(),
        })
    } else {
        if rest.len() != 2 {
            return Err(DecodeError::MalformedError);
        }
        let code = extract_string(&rest[0]).ok_or(DecodeError::MalformedError)?;
        let message = extract_string(&rest[1]).ok_or(DecodeError::MalformedError)?;
        Ok(FsReply::Err(FsError { code, message }))
    }
}

fn list_elements(expr: &Expr) -> Option<&Vec<Par>> {
    match &expr.expr_instance {
        Some(ExprInstance::EListBody(EList { ps, .. })) => Some(ps),
        Some(ExprInstance::ETupleBody(ETuple { ps, .. })) => Some(ps),
        _ => None,
    }
}

fn extract_bool(par: &Par) -> Option<bool> {
    match par.exprs.first()?.expr_instance.as_ref()? {
        ExprInstance::GBool(b) => Some(*b),
        _ => None,
    }
}

fn extract_string(par: &Par) -> Option<String> {
    match par.exprs.first()?.expr_instance.as_ref()? {
        ExprInstance::GString(s) => Some(s.clone()),
        _ => None,
    }
}

/// Extract raw bytes from a Par whose first expr is `GByteArray`. Used by
/// callers that just want the payload of a `[true, bytes]` reply.
pub fn par_as_bytes(par: &Par) -> Option<&[u8]> {
    match par.exprs.first()?.expr_instance.as_ref()? {
        ExprInstance::GByteArray(b) => Some(b),
        _ => None,
    }
}

/// Extract an i64 from a Par whose first expr is `GInt`.
pub fn par_as_int(par: &Par) -> Option<i64> {
    match par.exprs.first()?.expr_instance.as_ref()? {
        ExprInstance::GInt(i) => Some(*i),
        _ => None,
    }
}

/// Extract a bool from a Par whose first expr is `GBool`.
pub fn par_as_bool(par: &Par) -> Option<bool> {
    extract_bool(par)
}

/// Extract a String clone from a Par whose first expr is `GString`.
pub fn par_as_string(par: &Par) -> Option<String> {
    extract_string(par)
}

/// Extract a URI from a Par whose first expr is `GUri`. Rholang's
/// registry (`insertArbitrary`) returns `rho:id:<base58>` as a
/// `GUri`, distinct from `GString`.
pub fn par_as_uri(par: &Par) -> Option<String> {
    match par.exprs.first()?.expr_instance.as_ref()? {
        ExprInstance::GUri(s) => Some(s.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error_codes::FSERR_NOT_FOUND;

    fn bool_par(b: bool) -> Par {
        Par {
            exprs: vec![Expr {
                expr_instance: Some(ExprInstance::GBool(b)),
            }],
            ..Par::default()
        }
    }

    fn int_par(i: i64) -> Par {
        Par {
            exprs: vec![Expr {
                expr_instance: Some(ExprInstance::GInt(i)),
            }],
            ..Par::default()
        }
    }

    fn string_par(s: &str) -> Par {
        Par {
            exprs: vec![Expr {
                expr_instance: Some(ExprInstance::GString(s.to_string())),
            }],
            ..Par::default()
        }
    }

    fn bytes_par(b: &[u8]) -> Par {
        Par {
            exprs: vec![Expr {
                expr_instance: Some(ExprInstance::GByteArray(b.to_vec())),
            }],
            ..Par::default()
        }
    }

    fn list_par(items: Vec<Par>) -> Par {
        Par {
            exprs: vec![Expr {
                expr_instance: Some(ExprInstance::EListBody(EList {
                    ps: items,
                    ..EList::default()
                })),
            }],
            ..Par::default()
        }
    }

    #[test]
    fn ok_reply_with_no_payload() {
        let par = list_par(vec![bool_par(true)]);
        match decode_reply(&[par]).unwrap() {
            FsReply::Ok { payload } => assert!(payload.is_empty()),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn ok_reply_with_bytes_payload() {
        let par = list_par(vec![bool_par(true), bytes_par(b"hello")]);
        match decode_reply(&[par]).unwrap() {
            FsReply::Ok { payload } => {
                assert_eq!(payload.len(), 1);
                assert_eq!(par_as_bytes(&payload[0]), Some(&b"hello"[..]));
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn ok_reply_with_int_payload() {
        let par = list_par(vec![bool_par(true), int_par(42)]);
        match decode_reply(&[par]).unwrap() {
            FsReply::Ok { payload } => assert_eq!(par_as_int(&payload[0]), Some(42)),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn err_reply_parses_code_and_msg() {
        let par = list_par(vec![
            bool_par(false),
            string_par(FSERR_NOT_FOUND),
            string_par("file missing"),
        ]);
        match decode_reply(&[par]).unwrap() {
            FsReply::Err(e) => {
                assert_eq!(e.code, FSERR_NOT_FOUND);
                assert_eq!(e.message, "file missing");
                assert!(e.is_known());
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn err_reply_with_unknown_code_is_still_decoded() {
        let par = list_par(vec![
            bool_par(false),
            string_par("FSERR_NEW_HOTNESS"),
            string_par("TBD"),
        ]);
        match decode_reply(&[par]).unwrap() {
            FsReply::Err(e) => {
                assert_eq!(e.code, "FSERR_NEW_HOTNESS");
                assert!(!e.is_known());
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn no_reply_returns_no_reply_error() {
        assert!(matches!(decode_reply(&[]), Err(DecodeError::NoReply)));
    }

    #[test]
    fn too_many_replies_errors() {
        let a = list_par(vec![bool_par(true)]);
        let b = list_par(vec![bool_par(true)]);
        assert!(matches!(
            decode_reply(&[a, b]),
            Err(DecodeError::TooManyReplies(2))
        ));
    }

    #[test]
    fn non_list_reply_errors() {
        assert!(matches!(
            decode_reply(&[int_par(5)]),
            Err(DecodeError::NotListLike)
        ));
    }

    #[test]
    fn malformed_err_reply_errors() {
        let par = list_par(vec![bool_par(false), string_par("FSERR_BAD_ARG")]);
        assert!(matches!(
            decode_reply(&[par]),
            Err(DecodeError::MalformedError)
        ));
    }
}
