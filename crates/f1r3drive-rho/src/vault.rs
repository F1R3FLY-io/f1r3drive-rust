//! `rho:vault:system` operations.
//!
//! A distinct snippet family from the `Fs` agent ones in
//! [`crate::snippet`]: vault terms look up a *different* registry URN
//! (`rho:vault:system`) and don't share the `[true, ...] / [false,
//! code, msg]` reply shape — the balance query returns a bare int on
//! success and a bare string (the vault's own error message) on
//! failure. The decoder here captures that shape explicitly.
//!
//! Mirrors `RholangExpressionConstructor.checkBalanceRho` in the Java
//! f1r3drive, which is itself the Rholang shape blessed by the
//! `rho:vault:system` system contract. The on-wire term is kept
//! textually close to the Java one so a side-by-side diff with the
//! Scala-era f1r3drive is unambiguous.
//!
//! Only balance read is implemented here. Transfer / deposit will land
//! with Stage 4 of the tokens-as-files feature.

use f1r3drive_proto::rhoapi::expr::ExprInstance;
use f1r3drive_proto::rhoapi::Par;
use thiserror::Error;

use crate::snippet::Snippet;

/// Build the `rho:vault:system → findOrCreate → balance` Rholang
/// program for a REV address. Suitable for `exploratory_deploy` — no
/// signing or propose required.
pub fn check_balance_snippet(rev_address: &str) -> Snippet {
    // Keep the string shape close to Java's StringBuilder output so
    // the two are easy to diff. The server parses either shape
    // identically; whitespace is not consensus-visible.
    //
    // Reply shape on the `return` channel:
    //   - `balance`  — GInt, when `findOrCreate` yields `(true, vault)`
    //                  and `@vault!("balance", *return)` resolves
    //   - `err`      — GString, when `findOrCreate` yields
    //                  `(false, err)` (e.g. "Invalid address")
    let body = format!(
        "new return, rl(`rho:registry:lookup`), SystemVaultCh, vaultCh in {{\n  \
         rl!(`rho:vault:system`, *SystemVaultCh) |\n  \
         for (@(_, SystemVault) <- SystemVaultCh) {{\n    \
         @SystemVault!(\"findOrCreate\", \"{addr}\", *vaultCh) |\n    \
         for (@maybeVault <- vaultCh) {{\n      \
         match maybeVault {{\n        \
         (true, vault) => @vault!(\"balance\", *return)\n        \
         (false, err) => return!(err)\n      \
         }}\n    \
         }}\n  \
         }}\n\
         }}\n",
        addr = rev_address,
    );
    Snippet(body)
}

/// Build a `rho:vault:system → transfer` Rholang program.
///
/// Mirrors `RholangExpressionConstructor.transfer` on the Java
/// f1r3drive. Reply shape (on `rho:system:deployId`):
///   `(true, "Transfer successful (not yet finalized).")` or
///   `(false, err)`.
///
/// We don't decode the reply from the mutating-deploy path (the
/// server surfaces it on the deployId channel which lands in the
/// block's cost record, not on `post_block_data`). The daemon's
/// mutating flow currently treats admit + propose as success; a
/// future stage could poll `getDeployData` for the deployId reply
/// to catch "insufficient funds" style vault-side errors.
pub fn transfer_snippet(from_addr: &str, to_addr: &str, amount: i64) -> Snippet {
    let body = format!(
        "new rl(`rho:registry:lookup`), SystemVaultCh in {{\n  \
         rl!(`rho:vault:system`, *SystemVaultCh) |\n  \
         for (@(_, SystemVault) <- SystemVaultCh) {{\n    \
         new vaultCh, vaultTo, authKeyCh, \
         deployerId(`rho:system:deployerId`), \
         deployId(`rho:system:deployId`) \
         in {{\n      \
         match (\"{from}\", \"{to}\", {amount}) {{\n        \
         (vaultAddrFrom, vaultAddrTo, amount) => {{\n          \
         @SystemVault!(\"findOrCreate\", vaultAddrFrom, *vaultCh) |\n          \
         @SystemVault!(\"findOrCreate\", vaultAddrTo, *vaultTo) |\n          \
         @SystemVault!(\"deployerAuthKey\", *deployerId, *authKeyCh) |\n          \
         for (@vault <- vaultCh; key <- authKeyCh; _ <- vaultTo) {{\n            \
         match vault {{\n              \
         (true, vault) => {{\n                \
         new resultCh in {{\n                  \
         @vault!(\"transfer\", vaultAddrTo, amount, *key, *resultCh) |\n                  \
         for (@result <- resultCh) {{\n                    \
         match result {{\n                      \
         (true, _) => deployId!((true, \"Transfer successful (not yet finalized).\"))\n                      \
         (false, err) => deployId!((false, err))\n                    \
         }}\n                  \
         }}\n                \
         }}\n              \
         }}\n              \
         err => {{\n                \
         deployId!((false, \"System vault cannot be found or created.\"))\n              \
         }}\n            \
         }}\n          \
         }}\n        \
         }}\n      \
         }}\n    \
         }}\n  \
         }}\n\
         }}\n",
        from = from_addr,
        to = to_addr,
        amount = amount,
    );
    Snippet(body)
}

/// Decode error for a `rho:vault:system → balance` reply.
#[derive(Debug, Error)]
pub enum BalanceError {
    #[error("no reply received (deploy produced no data at the return channel)")]
    NoReply,
    #[error("expected a single reply Par, got {0}")]
    TooManyReplies(usize),
    #[error("vault reply has no exprs")]
    EmptyPar,
    #[error("vault returned error: {0}")]
    VaultError(String),
    #[error("balance ({0} bytes signed BE) does not fit in i64")]
    BalanceOverflow(usize),
    #[error("unexpected reply shape (not int, bigint, or string)")]
    UnexpectedShape,
}

/// Decode a `check_balance` reply. Returns the balance in REV (the
/// chain's smallest denomination) on success. The vault's own
/// "address invalid" / "vault not found" errors come back as
/// [`BalanceError::VaultError`] with the free-form string the vault
/// produced — the daemon can turn that into a user-visible warning.
///
/// The on-chain balance is a Rholang `BigInt` (surfaced as
/// `GBigInt(bytes_signed_be)`). Legacy / unit-test shards may also
/// return a plain `GInt`; both decode here. Values outside `i64`
/// range come back as [`BalanceError::BalanceOverflow`] — in
/// practice no REV wallet is anywhere near 2^63, so this is a
/// defensive guard rather than an expected error.
pub fn decode_balance_reply(pars: &[Par]) -> Result<i64, BalanceError> {
    match pars.len() {
        0 => return Err(BalanceError::NoReply),
        1 => (),
        n => return Err(BalanceError::TooManyReplies(n)),
    }
    let par = &pars[0];
    let first = par.exprs.first().ok_or(BalanceError::EmptyPar)?;
    match first.expr_instance.as_ref() {
        Some(ExprInstance::GInt(n)) => Ok(*n),
        Some(ExprInstance::GBigInt(bytes)) => bigint_be_to_i64(bytes),
        Some(ExprInstance::GString(s)) => Err(BalanceError::VaultError(s.clone())),
        _ => Err(BalanceError::UnexpectedShape),
    }
}

/// Decode big-endian signed two's-complement bytes to i64. Mirrors
/// `rho_type::bytes_to_bigint` on f1r3node-rust but narrowed to i64.
/// Empty input is `0` (consistent with Rholang's `0n`).
fn bigint_be_to_i64(bytes: &[u8]) -> Result<i64, BalanceError> {
    if bytes.is_empty() {
        return Ok(0);
    }
    // Sign-extend / check fit. If byte count > 8 and the extra bytes
    // aren't the sign extension of the 9th-from-last byte, we
    // overflow; if ≤ 8, sign-extend to 8 bytes.
    if bytes.len() > 8 {
        let sign_byte = if (bytes[0] & 0x80) != 0 { 0xff } else { 0x00 };
        let extra = bytes.len() - 8;
        if bytes[..extra].iter().any(|&b| b != sign_byte) {
            return Err(BalanceError::BalanceOverflow(bytes.len()));
        }
        let tail: [u8; 8] = bytes[extra..].try_into().unwrap();
        return Ok(i64::from_be_bytes(tail));
    }
    let sign_byte = if (bytes[0] & 0x80) != 0 { 0xff } else { 0x00 };
    let mut extended = [sign_byte; 8];
    extended[8 - bytes.len()..].copy_from_slice(bytes);
    Ok(i64::from_be_bytes(extended))
}

#[cfg(test)]
mod tests {
    use super::*;
    use f1r3drive_proto::rhoapi::Expr;

    fn int_par(i: i64) -> Par {
        Par {
            exprs: vec![Expr {
                expr_instance: Some(ExprInstance::GInt(i)),
            }],
            ..Par::default()
        }
    }

    fn bigint_par(bytes: Vec<u8>) -> Par {
        Par {
            exprs: vec![Expr {
                expr_instance: Some(ExprInstance::GBigInt(bytes)),
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

    #[test]
    fn snippet_contains_vault_urn_and_address() {
        let s = check_balance_snippet("1111AtahZeefej4tvVR6ti9TJtv8yxLebT31SCEVDCKMNikBk5r3g");
        let term = s.term();
        assert!(term.contains("rho:vault:system"));
        assert!(term.contains("findOrCreate"));
        assert!(term.contains("1111AtahZeefej4tvVR6ti9TJtv8yxLebT31SCEVDCKMNikBk5r3g"));
        // Must bind `return` at the top-level `new` — the server pulls
        // the deploy result from the first unforgeable name allocated.
        assert!(term.starts_with("new return"));
    }

    #[test]
    fn transfer_snippet_shape() {
        let s = transfer_snippet(
            "1111AtahZeefej4tvVR6ti9TJtv8yxLebT31SCEVDCKMNikBk5r3g",
            "1111AaaaBbbbCcccDdddEeeeFfffGgggHhhhIiiiJjjjKkkkLmmno",
            1_000_000,
        );
        let term = s.term();
        assert!(term.contains("rho:vault:system"));
        // Both from and to addresses embedded verbatim.
        assert!(term.contains("1111AtahZeefej4tvVR6ti9TJtv8yxLebT31SCEVDCKMNikBk5r3g"));
        assert!(term.contains("1111AaaaBbbbCcccDdddEeeeFfffGgggHhhhIiiiJjjjKkkkLmmno"));
        // Amount embedded as a bare integer literal.
        assert!(term.contains("1000000"));
        // Both system fixed channels used by the vault.
        assert!(term.contains("rho:system:deployerId"));
        assert!(term.contains("rho:system:deployId"));
        // Transfer verb called on the inner vault.
        assert!(term.contains("@vault!(\"transfer\""));
    }

    #[test]
    fn decode_balance_from_int_reply() {
        assert_eq!(
            decode_balance_reply(&[int_par(50_000_000_000_000_000)]).unwrap(),
            50_000_000_000_000_000,
        );
    }

    #[test]
    fn decode_balance_from_zero_reply() {
        assert_eq!(decode_balance_reply(&[int_par(0)]).unwrap(), 0);
    }

    #[test]
    fn decode_vault_error_from_string_reply() {
        let err = decode_balance_reply(&[string_par("Invalid address")]).unwrap_err();
        assert!(matches!(err, BalanceError::VaultError(s) if s == "Invalid address"));
    }

    #[test]
    fn decode_empty_pars_errors() {
        assert!(matches!(
            decode_balance_reply(&[]),
            Err(BalanceError::NoReply)
        ));
    }

    #[test]
    fn decode_too_many_pars_errors() {
        assert!(matches!(
            decode_balance_reply(&[int_par(1), int_par(2)]),
            Err(BalanceError::TooManyReplies(2))
        ));
    }

    #[test]
    fn decode_balance_from_bigint_reply() {
        // 50 quadrillion as signed big-endian bytes:
        // 50_000_000_000_000_000 = 0x00_B1_A2_BC_2E_C5_00_00
        let bal = 50_000_000_000_000_000i64;
        let bytes = bal.to_be_bytes().to_vec();
        assert_eq!(decode_balance_reply(&[bigint_par(bytes)]).unwrap(), bal);
    }

    #[test]
    fn decode_bigint_zero_shapes() {
        // Rholang represents 0 as either an empty byte vec or [0].
        assert_eq!(decode_balance_reply(&[bigint_par(vec![])]).unwrap(), 0);
        assert_eq!(decode_balance_reply(&[bigint_par(vec![0])]).unwrap(), 0);
    }

    #[test]
    fn decode_bigint_narrow_values_sign_extend() {
        // 1-byte 0x01 → 1. 1-byte 0xff → -1 (signed BE).
        assert_eq!(decode_balance_reply(&[bigint_par(vec![0x01])]).unwrap(), 1);
        assert_eq!(decode_balance_reply(&[bigint_par(vec![0xff])]).unwrap(), -1);
        // 2-byte 0xff_00 → -256
        assert_eq!(
            decode_balance_reply(&[bigint_par(vec![0xff, 0x00])]).unwrap(),
            -256,
        );
    }

    #[test]
    fn decode_bigint_overflow_errors() {
        // 9-byte positive value with a non-zero top byte can't fit in i64.
        let too_big = vec![0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(matches!(
            decode_balance_reply(&[bigint_par(too_big)]),
            Err(BalanceError::BalanceOverflow(9)),
        ));
    }

    #[test]
    fn decode_bigint_zero_padded_positive_fits() {
        // 9-byte representation of a positive i64 (leading 0 is sign
        // padding) should decode without error.
        let bal = 1_000_000i64;
        let mut bytes = vec![0x00];
        bytes.extend_from_slice(&bal.to_be_bytes());
        assert_eq!(decode_balance_reply(&[bigint_par(bytes)]).unwrap(), bal);
    }

    #[test]
    fn decode_unexpected_shape_errors() {
        let bool_par = Par {
            exprs: vec![Expr {
                expr_instance: Some(ExprInstance::GBool(true)),
            }],
            ..Par::default()
        };
        assert!(matches!(
            decode_balance_reply(&[bool_par]),
            Err(BalanceError::UnexpectedShape),
        ));
    }
}
