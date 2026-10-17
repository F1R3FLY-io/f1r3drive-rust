//! Base58 encoding used by REV addresses.
//!
//! Ported byte-for-byte from
//! `f1r3node-rust/rholang/src/rust/interpreter/util/base58.rs`, which
//! in turn mirrors Rholang's `coop.rchain.rholang.interpreter.util.
//! codec.Base58`. The alphabet below is the Bitcoin alphabet, same as
//! what the rest of the network uses — we re-port rather than pull in
//! `bs58` because the stdlib-only version is tiny and we avoid any
//! risk of alphabet drift from an upstream crate update.

const ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn encode(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }

    let leading_zeros = input.iter().take_while(|&&byte| byte == 0).count();

    let mut num = Vec::from(input);
    let mut encoded = String::new();

    while !num.is_empty() {
        let mut remainder = 0usize;
        let mut new_num = Vec::new();

        for &byte in &num {
            let temp = (remainder << 8) + byte as usize;
            let div = temp / 58;
            remainder = temp % 58;
            if !new_num.is_empty() || div != 0 {
                new_num.push(div as u8);
            }
        }

        encoded.push(ALPHABET.chars().nth(remainder).unwrap());
        num = new_num;
    }

    for _ in 0..leading_zeros {
        encoded.push(ALPHABET.chars().next().unwrap());
    }

    encoded.chars().rev().collect()
}

pub fn decode(input: &str) -> Result<Vec<u8>, String> {
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let mut bytes: Vec<u8> = Vec::new();

    for c in input.chars() {
        let value = ALPHABET
            .find(c)
            .ok_or_else(|| format!("Invalid Base58 character: {c}"))?;

        let mut carry = value;
        for byte in bytes.iter_mut().rev() {
            let temp = (*byte as usize) * 58 + carry;
            *byte = (temp & 0xFF) as u8;
            carry = temp >> 8;
        }

        while carry > 0 {
            bytes.insert(0, (carry & 0xFF) as u8);
            carry >>= 8;
        }
    }

    let leading_ones = input.chars().take_while(|&c| c == '1').count();
    let mut decoded = vec![0u8; leading_ones];
    decoded.extend(bytes);

    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip on REV-shaped inputs: 4 zero bytes of prefix
    /// followed by 36 non-zero bytes (key_hash + checksum). This is
    /// the only shape the encoder is contractually guaranteed to
    /// round-trip through the decoder — the ported impl has an
    /// off-by-one on *bare* all-zero inputs (see
    /// `encode_bare_zero_byte_quirk` below), but 4-byte zero
    /// prefixes compose correctly because the loop body contributes
    /// a non-empty encoding before the leading-ones get appended.
    #[test]
    fn roundtrip_rev_shaped_payloads() {
        let samples: &[Vec<u8>] = &[
            {
                let mut v = vec![0u8; 4];
                v.extend([0x12, 0x34, 0x56, 0x78].iter().copied().cycle().take(36));
                v
            },
            {
                let mut v = vec![0u8; 4];
                v.extend((0u8..36).collect::<Vec<_>>());
                v
            },
            {
                let mut v = vec![0u8; 4];
                v.extend([0xff; 36]);
                v
            },
        ];
        for s in samples {
            let encoded = encode(s);
            let decoded = decode(&encoded).expect("decode valid base58");
            assert_eq!(&decoded, s, "roundtrip mismatch for {s:?}");
        }
    }

    /// Round-trip on pure-non-zero inputs, which also compose
    /// correctly (no leading-zero accounting involved).
    #[test]
    fn roundtrip_non_zero_payloads() {
        let samples: &[&[u8]] = &[
            &[0xff],
            &[0xde, 0xad, 0xbe, 0xef],
            &[0x01, 0x80, 0x7f, 0xa5, 0x33, 0x29, 0x14, 0xc2],
        ];
        for &s in samples {
            let encoded = encode(s);
            let decoded = decode(&encoded).expect("decode valid base58");
            assert_eq!(decoded, s, "roundtrip mismatch for {s:?}");
        }
    }

    /// Documented quirk of the ported impl: `encode([0])` returns
    /// `"11"` (and `decode("11")` returns `[0, 0]`), so the pair is
    /// not an inverse for a single zero byte. This does NOT affect
    /// REV addresses — the prefix is a *4*-byte zero block whose
    /// loop iteration pushes a `1` into the body before the
    /// leading-ones for the zeros get appended, keeping the overall
    /// encoding faithful. We pin the current behaviour as a
    /// regression guard; changing it would re-diverge from
    /// `f1r3node-rust`'s matching port and break address parsing.
    #[test]
    fn encode_bare_zero_byte_quirk() {
        assert_eq!(encode(&[0]), "11");
        assert_eq!(encode(&[0, 0]), "111");
        assert_eq!(decode("11").unwrap(), vec![0, 0]);
    }

    #[test]
    fn decode_rejects_invalid_chars() {
        // '0', 'O', 'I', 'l' are excluded from the Bitcoin alphabet.
        assert!(decode("0").is_err());
        assert!(decode("O").is_err());
        assert!(decode("I").is_err());
        assert!(decode("l").is_err());
    }

    #[test]
    fn empty_in_empty_out() {
        assert_eq!(encode(&[]), "");
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }
}
