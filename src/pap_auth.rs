// Copyright (c) 2025 Denys Fedoryshchenko <denys.f@collabora.com>
// SPDX-License-Identifier: Apache-2.0

use std::fmt::Write as _;

use md5::{Digest, Md5};

use crate::Result;

pub fn decrypt_user_password(
    encrypted: &[u8],
    secret: &str,
    request_authenticator: &[u8; 16],
) -> Result<Vec<u8>> {
    let aligned = encrypted.len() / 16 * 16 == encrypted.len();
    if encrypted.is_empty() || !aligned {
        return Err("invalid User-Password attribute length".into());
    }
    let mut result = Vec::with_capacity(encrypted.len());
    let mut last_block = *request_authenticator;
    for chunk in encrypted.chunks(16) {
        let mut ctx = Md5::new();
        ctx.update(secret.as_bytes());
        ctx.update(last_block);
        let hash = ctx.finalize();
        let mut plain_block = vec![0u8; chunk.len()];
        for (i, byte) in chunk.iter().enumerate() {
            plain_block[i] = byte ^ hash[i];
        }
        last_block = chunk
            .try_into()
            .map_err(|_| "invalid chunk size in PAP password")?;
        result.extend_from_slice(&plain_block);
    }
    Ok(result)
}

pub fn format_password_debug(password: &[u8]) -> String {
    match String::from_utf8(password.to_vec()) {
        Ok(text) => format!("'{}'", text),
        Err(_) => format!("hex={}", bytes_to_hex(password)),
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut out, "{:02x}", byte);
    }
    out
}

pub fn trim_trailing_zeros(data: &[u8]) -> &[u8] {
    if let Some(pos) = data.iter().rposition(|b| *b != 0) {
        &data[..=pos]
    } else {
        &data[0..0]
    }
}

/// Detect NUL bytes in the middle of the decrypted PAP payload.
///
/// RFC 2865 only places NULs at the end (as padding to a 16-byte multiple),
/// so an interior NUL suggests a wrong shared secret, corruption, or a
/// non-conforming client. Callers should log a warning when this is true.
pub fn has_interior_nul(decrypted: &[u8]) -> bool {
    match decrypted.iter().rposition(|b| *b != 0) {
        Some(last_nonzero) => decrypted[..last_nonzero].contains(&0),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use md5::{Digest, Md5};

    fn encrypt_password(clear: &[u8], secret: &str, auth: &[u8; 16]) -> Vec<u8> {
        let mut padded = clear.to_vec();
        if padded.is_empty() {
            padded.resize(16, 0);
        } else if padded.len() / 16 * 16 != padded.len() {
            let pad = 16 - (padded.len() % 16);
            padded.resize(padded.len() + pad, 0);
        }
        let mut result = Vec::with_capacity(padded.len());
        let mut last_block = *auth;
        for chunk in padded.chunks(16) {
            let mut ctx = Md5::new();
            ctx.update(secret.as_bytes());
            ctx.update(last_block);
            let hash = ctx.finalize();
            let mut cipher_block = [0u8; 16];
            for (i, byte) in chunk.iter().enumerate() {
                cipher_block[i] = byte ^ hash[i];
            }
            result.extend_from_slice(&cipher_block[..chunk.len()]);
            last_block = cipher_block;
        }
        result
    }

    #[test]
    fn decrypts_ascii_password() {
        let auth = [0x10u8; 16];
        let secret = "testing123";
        let encrypted = encrypt_password(b"pass", secret, &auth);
        let decrypted = decrypt_user_password(&encrypted, secret, &auth).unwrap();
        assert!(decrypted.starts_with(b"pass"));
        assert_eq!(decrypted.len(), 16);
    }

    #[test]
    fn decrypts_non_utf8_password() {
        let auth = [0xabu8; 16];
        let secret = "sharedsecret";
        let raw = vec![0xff, 0xfe, 0xfd];
        let encrypted = encrypt_password(&raw, secret, &auth);
        let decrypted = decrypt_user_password(&encrypted, secret, &auth).unwrap();
        assert!(decrypted.starts_with(&raw));
        assert_eq!(decrypted.len(), 16);
    }

    #[test]
    fn formats_password_debug_hex_for_non_utf8() {
        let rendered = format_password_debug(&[0xff, 0x00]);
        assert!(rendered.starts_with("hex="));
    }

    #[test]
    fn detects_interior_nuls() {
        // Trailing NULs only = padding, no warning.
        assert!(!has_interior_nul(b"pass\0\0\0\0"));
        assert!(!has_interior_nul(b"pass"));
        // All zeros (empty password, fully padded) = no interior NUL.
        assert!(!has_interior_nul(&[0u8; 16]));
        // NUL before the last non-null byte is suspicious.
        assert!(has_interior_nul(b"pa\0ss"));
        assert!(has_interior_nul(b"\0pass\0\0"));
    }

    #[test]
    fn trims_padding_but_keeps_non_zero_suffix() {
        let data = [b'p', b'a', b's', b's', 0, 0];
        assert_eq!(trim_trailing_zeros(&data), b"pass");

        let data_with_zero = [b'p', b'a', b's', 0];
        assert_eq!(trim_trailing_zeros(&data_with_zero), b"pas");
    }
}
