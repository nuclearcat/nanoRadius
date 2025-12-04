// Copyright (c) 2025 Denys Fedoryshchenko <denys.f@collabora.com>
// SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-Proprietary

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;

use md5::{Digest, Md5};

use crate::Dictionary;
use crate::NasDevice;
use crate::logger::Logger;
use crate::radius::{RadiusCode, RadiusPacket};

pub fn handle_accounting_packet(
    data: &[u8],
    src: SocketAddr,
    socket: &UdpSocket,
    nas_map: &HashMap<IpAddr, Arc<NasDevice>>,
    debug: bool,
    logger: &Logger,
    dictionary: &Dictionary,
) {
    let Some(nas) = nas_map.get(&src.ip()).cloned() else {
        logger.log(
            "WARN",
            &format!("Accounting request from unknown NAS {}", src.ip()),
        );
        return;
    };
    let packet = match RadiusPacket::parse(data) {
        Ok(packet) => packet,
        Err(err) => {
            logger.log("WARN", &format!("Invalid accounting packet: {err}"));
            return;
        }
    };
    if packet.code != RadiusCode::AccountingRequest as u8 {
        logger.log(
            "WARN",
            &format!("Unsupported accounting code {} from {}", packet.code, src),
        );
        return;
    }

    match RadiusPacket::verify_message_authenticator(data, &nas.secret) {
        Ok(Some(false)) => {
            logger.log(
                "WARN",
                &format!("Bad Message-Authenticator from {}", src.ip()),
            );
            return;
        }
        Ok(_) => {}
        Err(err) => {
            logger.log(
                "WARN",
                &format!("Failed to verify Message-Authenticator: {err}"),
            );
            return;
        }
    }

    if !verify_accounting_authenticator(data, &packet, &nas.secret) {
        logger.log(
            "WARN",
            &format!("Bad accounting authenticator from {}", src.ip()),
        );
        return;
    }

    let username = packet
        .attribute_value(1)
        .and_then(|v| String::from_utf8(v.to_vec()).ok())
        .unwrap_or_else(|| "<unknown>".to_string());
    let acct_type = packet
        .attribute_value(40)
        .and_then(parse_u32)
        .and_then(|v| dictionary.acct_status_label(v).or(Some("Unknown")))
        .unwrap_or("Unknown");
    log_acct_record(logger, &nas, src, &username, acct_type);
    if debug {
        let attributes = dictionary.describe_attributes(&packet.attributes);
        logger.debug(true, &format!("Attributes: {}", attributes));
    }

    match RadiusPacket::build_response(RadiusCode::AccountingResponse, &packet, &nas.secret, &[]) {
        Ok(response) => {
            if let Err(err) = socket.send_to(&response, src) {
                logger.log(
                    "ERROR",
                    &format!("Failed to send accounting response: {err}"),
                );
            }
        }
        Err(err) => logger.log(
            "ERROR",
            &format!("Failed to build accounting response: {err}"),
        ),
    }
}

pub fn verify_accounting_authenticator(data: &[u8], packet: &RadiusPacket, secret: &str) -> bool {
    if data.len() < packet.length as usize {
        return false;
    }
    let mut ctx = Md5::new();
    ctx.update(&data[0..4]);
    ctx.update([0u8; 16]);
    ctx.update(&data[20..packet.length as usize]);
    ctx.update(secret.as_bytes());
    let digest = ctx.finalize();
    digest.as_slice() == packet.authenticator
}

fn parse_u32(value: &[u8]) -> Option<u32> {
    if value.len() == 4 {
        Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
    } else {
        None
    }
}

fn log_acct_record(logger: &Logger, nas: &NasDevice, src: SocketAddr, user: &str, status: &str) {
    logger.log(
        "INFO",
        &format!(
            "[ACCT {}] user={} nas={} ip={}",
            status,
            user,
            nas.shortname
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            src.ip()
        ),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_attr() -> Vec<u8> {
        vec![1u8, 7, b'a', b'l', b'i', b'c', b'e'] // type=User-Name, len=7, value="alice"
    }

    fn build_acct_request(secret: &str, attrs: &[u8]) -> Vec<u8> {
        let length = 20 + attrs.len();
        let mut data = Vec::with_capacity(length);
        data.push(RadiusCode::AccountingRequest as u8);
        data.push(1); // identifier
        data.extend_from_slice(&(length as u16).to_be_bytes());
        data.extend_from_slice(&[0u8; 16]); // authenticator placeholder
        data.extend_from_slice(attrs);

        let mut ctx = Md5::new();
        ctx.update(&data[0..4]);
        ctx.update(&data[4..20]); // zeroes
        if length > 20 {
            ctx.update(&data[20..]);
        }
        ctx.update(secret.as_bytes());
        let digest = ctx.finalize();
        data[4..20].copy_from_slice(digest.as_slice());
        data
    }

    #[test]
    fn authenticator_validates_request() {
        let secret = "shared";
        let packet_bytes = build_acct_request(secret, &user_attr());
        let parsed = RadiusPacket::parse(&packet_bytes).expect("parse succeeds");

        assert!(verify_accounting_authenticator(
            &packet_bytes,
            &parsed,
            secret
        ));
    }

    #[test]
    fn authenticator_fails_with_tampered_payload() {
        let secret = "shared";
        let mut packet_bytes = build_acct_request(secret, &user_attr());
        let last = packet_bytes.len() - 1;
        packet_bytes[last] ^= 0xFF;
        let parsed = RadiusPacket::parse(&packet_bytes).expect("parse succeeds");

        assert!(!verify_accounting_authenticator(
            &packet_bytes,
            &parsed,
            secret
        ));
    }

    #[test]
    fn authenticator_fails_when_data_truncated() {
        let secret = "shared";
        let full = build_acct_request(secret, &user_attr());
        let parsed = RadiusPacket::parse(&full).expect("parse succeeds");

        let mut truncated = full.clone();
        truncated.truncate(10);

        assert!(!verify_accounting_authenticator(
            &truncated, &parsed, secret
        ));
    }

    #[test]
    fn authenticator_fails_when_truncated() {
        let secret = "shared";
        let mut packet_bytes = build_acct_request(secret, &user_attr());
        packet_bytes.truncate(10);
        assert!(RadiusPacket::parse(&packet_bytes).is_err());
    }
}
