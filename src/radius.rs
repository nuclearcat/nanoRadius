// Copyright (c) 2025 Denys Fedoryshchenko <denys.f@collabora.com>
// SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-Proprietary

use crate::Result;
use md5::{Digest, Md5};

#[derive(Clone)]
pub struct RadiusAttribute {
    pub typ: u8,
    pub data: Vec<u8>,
}

pub struct RadiusPacket {
    pub code: u8,
    pub identifier: u8,
    pub length: u16,
    pub authenticator: [u8; 16],
    pub attributes: Vec<RadiusAttribute>,
}

impl RadiusPacket {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 20 {
            return Err("radius packet too short".into());
        }
        let length = u16::from_be_bytes([data[2], data[3]]);
        if length as usize != data.len() || length < 20 {
            return Err("invalid RADIUS length".into());
        }
        let mut authenticator = [0u8; 16];
        authenticator.copy_from_slice(&data[4..20]);
        let mut attributes = Vec::new();
        let mut offset = 20usize;
        while offset < length as usize {
            if offset + 2 > length as usize {
                return Err("truncated attribute header".into());
            }
            let typ = data[offset];
            let attr_len = data[offset + 1] as usize;
            if attr_len < 2 || offset + attr_len > length as usize {
                return Err("invalid attribute length".into());
            }
            let value = data[offset + 2..offset + attr_len].to_vec();
            attributes.push(RadiusAttribute { typ, data: value });
            offset += attr_len;
        }
        Ok(Self {
            code: data[0],
            identifier: data[1],
            length,
            authenticator,
            attributes,
        })
    }

    pub fn attribute_value(&self, typ: u8) -> Option<&[u8]> {
        self.attributes
            .iter()
            .find(|attr| attr.typ == typ)
            .map(|attr| attr.data.as_slice())
    }

    pub fn build_response(
        code: RadiusCode,
        request: &RadiusPacket,
        secret: &str,
        attributes: &[RadiusAttribute],
    ) -> Result<Vec<u8>> {
        for attr in attributes {
            if attr.data.len() > 253 {
                return Err("attribute value too long (>253 bytes)".into());
            }
        }
        let attr_len: usize = attributes.iter().map(|a| a.data.len() + 2).sum();
        if attr_len + 20 > u16::MAX as usize {
            return Err("RADIUS packet length exceeds u16::MAX".into());
        }
        let length = (20 + attr_len) as u16;
        let mut buffer = Vec::with_capacity(length as usize);
        buffer.push(code as u8);
        buffer.push(request.identifier);
        buffer.extend_from_slice(&length.to_be_bytes());
        buffer.extend_from_slice(&[0u8; 16]);
        for attr in attributes {
            buffer.push(attr.typ);
            buffer.push((attr.data.len() + 2) as u8);
            buffer.extend_from_slice(&attr.data);
        }
        let mut ctx = Md5::new();
        ctx.update(&buffer[0..4]);
        ctx.update(&request.authenticator);
        if buffer.len() > 20 {
            ctx.update(&buffer[20..]);
        }
        ctx.update(secret.as_bytes());
        let digest = ctx.finalize();
        buffer[4..20].copy_from_slice(digest.as_slice());
        Ok(buffer)
    }

    pub fn verify_message_authenticator(data: &[u8], secret: &str) -> Result<Option<bool>> {
        if data.len() < 20 {
            return Err("radius packet too short".into());
        }
        let length = u16::from_be_bytes([data[2], data[3]]);
        if length as usize != data.len() {
            return Err("invalid RADIUS length".into());
        }
        let mut offset = 20usize;
        let mut mac_offset = None;
        while offset < data.len() {
            if offset + 2 > data.len() {
                return Err("truncated attribute header".into());
            }
            let typ = data[offset];
            let attr_len = data[offset + 1] as usize;
            if attr_len < 2 || offset + attr_len > data.len() {
                return Err("invalid attribute length".into());
            }
            if typ == 80 {
                mac_offset = Some((offset + 2, attr_len - 2));
                break;
            }
            offset += attr_len;
        }

        let Some((mac_pos, mac_len)) = mac_offset else {
            return Ok(None);
        };
        if mac_len != 16 {
            return Err("Message-Authenticator must be 16 bytes".into());
        }
        let mut packet = data.to_vec();
        for b in &mut packet[mac_pos..mac_pos + mac_len] {
            *b = 0;
        }
        let calc = hmac_md5(secret.as_bytes(), &packet);
        let provided = &data[mac_pos..mac_pos + mac_len];
        Ok(Some(constant_time_eq(&calc, provided)))
    }
}

#[repr(u8)]
pub enum RadiusCode {
    AccessRequest = 1,
    AccessAccept = 2,
    AccessReject = 3,
    AccountingRequest = 4,
    AccountingResponse = 5,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_access_request() {
        let mut data = vec![0u8; 20];
        data[0] = RadiusCode::AccessRequest as u8;
        data[1] = 7;
        data[2..4].copy_from_slice(&(20u16).to_be_bytes());
        data[4..20].copy_from_slice(&[0xabu8; 16]);

        let packet = RadiusPacket::parse(&data).expect("parse succeeds");
        assert_eq!(packet.code, RadiusCode::AccessRequest as u8);
        assert_eq!(packet.identifier, 7);
        assert_eq!(packet.length, 20);
        assert_eq!(packet.attributes.len(), 0);
    }

    #[test]
    fn build_response_uses_request_authenticator() {
        let request = RadiusPacket {
            code: RadiusCode::AccessRequest as u8,
            identifier: 5,
            length: 20,
            authenticator: [0x11; 16],
            attributes: Vec::new(),
        };
        let secret = "sharedsecret";
        let reply =
            RadiusPacket::build_response(RadiusCode::AccessAccept, &request, secret, &[]).unwrap();

        let parsed = RadiusPacket::parse(&reply).expect("response parses");
        assert_eq!(parsed.code, RadiusCode::AccessAccept as u8);
        assert_eq!(parsed.identifier, request.identifier);
        assert_eq!(parsed.length, 20);
        assert_ne!(parsed.authenticator, [0u8; 16]);

        // Validate authenticator matches MD5(header + request_auth + attrs + secret)
        let mut ctx = Md5::new();
        ctx.update(&reply[0..4]);
        ctx.update(&request.authenticator);
        ctx.update(secret.as_bytes());
        let expected = ctx.finalize();
        assert_eq!(parsed.authenticator, expected.as_slice());
    }

    #[test]
    fn rejects_attributes_over_253_bytes() {
        let request = RadiusPacket {
            code: RadiusCode::AccessRequest as u8,
            identifier: 1,
            length: 20,
            authenticator: [0u8; 16],
            attributes: Vec::new(),
        };
        let big_attr = RadiusAttribute {
            typ: 1,
            data: vec![0u8; 254],
        };
        let err =
            RadiusPacket::build_response(RadiusCode::AccessAccept, &request, "secret", &[big_attr])
                .unwrap_err();
        assert!(err.to_string().contains("too long"));
    }

    #[test]
    fn validates_message_authenticator() {
        let secret = "sharedsecret";
        let mut data = vec![
            RadiusCode::AccessRequest as u8,
            1,
            0,
            38, // length placeholder
        ];
        data.extend_from_slice(&[0x11; 16]); // authenticator
        // Message-Authenticator attr
        data.push(80);
        data.push(18);
        data.extend_from_slice(&[0u8; 16]); // placeholder
        let length = data.len() as u16;
        data[2..4].copy_from_slice(&length.to_be_bytes());

        let mac = hmac_md5(secret.as_bytes(), &data);
        let len = data.len();
        data[len - 16..len].copy_from_slice(&mac);

        let result = RadiusPacket::verify_message_authenticator(&data, secret).unwrap();
        assert_eq!(result, Some(true));
    }

    #[test]
    fn detects_bad_message_authenticator() {
        let secret = "sharedsecret";
        let mut data = vec![RadiusCode::AccessRequest as u8, 1, 0, 38];
        data.extend_from_slice(&[0x22; 16]);
        data.push(80);
        data.push(18);
        data.extend_from_slice(&[0u8; 16]);
        let length = data.len() as u16;
        data[2..4].copy_from_slice(&length.to_be_bytes());

        let mac = hmac_md5(secret.as_bytes(), &data);
        let len = data.len();
        data[len - 16..len].copy_from_slice(&mac);
        data[len - 1] ^= 0xFF;

        let result = RadiusPacket::verify_message_authenticator(&data, secret).unwrap();
        assert_eq!(result, Some(false));
    }
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        let mut ctx = Md5::new();
        ctx.update(key);
        key_block.copy_from_slice(&ctx.finalize());
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for i in 0..64 {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5c;
    }

    let mut inner = Md5::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Md5::new();
    outer.update(&opad);
    outer.update(inner_hash);
    let digest = outer.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}
