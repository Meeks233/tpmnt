//! Secret generation for `init`: strong passphrases (diceware or base64) and
//! recovery keys sourced from the kernel CSPRNG (/dev/urandom). No third-party
//! crypto crate — generation is CSPRNG bytes mapped to words or base64url.

use std::io::Read;

use crate::error::{Code, Error, Result};

/// EFF large diceware wordlist (7776 words, ~12.9 bits each).
const WORDLIST: &str = include_str!("data/eff_wordlist.txt");

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Read `n` random bytes from the kernel CSPRNG.
pub fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut f = std::fs::File::open("/dev/urandom")
        .map_err(|e| Error::new(Code::EInternal, format!("open /dev/urandom: {e}")))?;
    let mut buf = vec![0u8; n];
    f.read_exact(&mut buf)
        .map_err(|e| Error::new(Code::EInternal, format!("read /dev/urandom: {e}")))?;
    Ok(buf)
}

/// base64url (no padding) encoding.
fn b64url(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64URL[((n >> 18) & 63) as usize] as char);
        out.push(B64URL[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64URL[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL[(n & 63) as usize] as char);
        }
    }
    out
}

/// A uniformly random wordlist index in [0, len) via rejection sampling on a
/// u16 to avoid modulo bias.
fn uniform_index(len: usize) -> Result<usize> {
    let len = len as u32;
    let limit = u32::from(u16::MAX) + 1; // 65536
    let reject_from = limit - (limit % len);
    loop {
        let b = random_bytes(2)?;
        let v = (u32::from(b[0]) << 8) | u32::from(b[1]);
        if v < reject_from {
            return Ok((v % len) as usize);
        }
    }
}

/// Generate a strong passphrase. `format` is "diceware" or "base64".
/// Both target >= 256 bits of entropy.
pub fn generate_passphrase(format: &str) -> Result<String> {
    match format {
        "base64" => Ok(b64url(&random_bytes(32)?)), // 256 bits
        "diceware" => {
            let words: Vec<&str> = WORDLIST.lines().filter(|l| !l.is_empty()).collect();
            // 7776 words ~= 12.925 bits/word; 20 words ~= 258 bits.
            let mut chosen = Vec::with_capacity(20);
            for _ in 0..20 {
                chosen.push(words[uniform_index(words.len())?]);
            }
            Ok(chosen.join("-"))
        }
        other => Err(
            Error::new(Code::EConfig, format!("unknown --key-format: {other:?}"))
                .with_hint("use --key-format diceware or --key-format base64"),
        ),
    }
}

/// Generate a printable recovery key (256 bits, base64url).
pub fn generate_recovery_key() -> Result<String> {
    Ok(b64url(&random_bytes(32)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_known_vectors() {
        assert_eq!(b64url(b""), "");
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
        assert_eq!(b64url(b"foob"), "Zm9vYg");
    }

    #[test]
    fn diceware_has_enough_words_and_is_random() {
        let a = generate_passphrase("diceware").unwrap();
        let b = generate_passphrase("diceware").unwrap();
        assert_eq!(a.split('-').count(), 20);
        assert_ne!(a, b);
    }

    #[test]
    fn base64_passphrase_is_256_bits() {
        let p = generate_passphrase("base64").unwrap();
        // 32 bytes -> 43 base64url chars (no padding).
        assert_eq!(p.len(), 43);
    }

    #[test]
    fn unknown_format_errors() {
        assert!(generate_passphrase("rot13").is_err());
    }
}
