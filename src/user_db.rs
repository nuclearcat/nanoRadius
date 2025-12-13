// Copyright (c) 2025 Denys Fedoryshchenko <denys.f@collabora.com>
// SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-Proprietary

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

use crate::Result;
use crate::dictionary::Dictionary;
use crate::radius::RadiusAttribute;
use serde::Deserialize;

pub struct User {
    #[allow(dead_code)]
    pub name: String,
    pub password: String,
    pub reply: Vec<RadiusAttribute>,
}

pub struct UserDb {
    users: HashMap<String, User>,
}

impl UserDb {
    pub fn load(path: &Path, dictionary: &Dictionary) -> Result<Self> {
        let raw = fs::read_to_string(path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("failed to read user database {}: {}", path.display(), e),
            )
        })?;
        let parsed: RawUsers = toml::from_str(&raw)?;
        let mut users = HashMap::new();
        for entry in parsed.user {
            let reply_attrs = encode_reply_attrs(&entry.reply, dictionary)?;
            let user = User {
                name: entry.name.clone(),
                password: entry.password.clone(),
                reply: reply_attrs,
            };
            users.insert(entry.name, user);
        }
        Ok(Self { users })
    }

    pub fn get(&self, username: &str) -> Option<&User> {
        self.users.get(username)
    }

    pub fn get_password(&self, username: &str) -> Option<&str> {
        self.get(username).map(|u| u.password.as_str())
    }

    pub fn user_count(&self) -> usize {
        self.users.len()
    }

    #[cfg(test)]
    pub(crate) fn from_map(credentials: HashMap<String, String>) -> Self {
        let users = credentials
            .into_iter()
            .map(|(name, password)| {
                (
                    name.clone(),
                    User {
                        name,
                        password,
                        reply: Vec::new(),
                    },
                )
            })
            .collect();
        Self { users }
    }
}

pub fn verify_credentials(username: &str, password: &[u8], db: &UserDb) -> bool {
    match db.get(username) {
        Some(user) => user.password.as_bytes() == password,
        None => false,
    }
}

fn encode_reply_attrs(reply: &[RawReply], dictionary: &Dictionary) -> Result<Vec<RadiusAttribute>> {
    let mut out = Vec::new();
    for attr in reply {
        // First try standard attributes
        if let Some(code) = dictionary.code_for_name(&attr.typ) {
            let data = encode_value(dictionary.meta(code).map(|m| m.kind), &attr.value)?;
            out.push(RadiusAttribute { typ: code, data });
            continue;
        }

        // Try vendor-specific attributes
        if let Some((vendor_id, vendor_type, vendor_meta)) =
            dictionary.lookup_vendor_attr(&attr.typ)
        {
            let value_data = encode_value(Some(vendor_meta.kind), &attr.value)?;
            let vsa_data = encode_vsa(vendor_id, vendor_type, &value_data)?;
            out.push(RadiusAttribute {
                typ: 26,
                data: vsa_data,
            });
            continue;
        }

        return Err(format!("unknown attribute type '{}'", attr.typ).into());
    }
    Ok(out)
}

fn encode_vsa(vendor_id: u32, vendor_type: u8, value: &[u8]) -> Result<Vec<u8>> {
    // VSA format: vendor-id (4 bytes) + vendor-type (1 byte) + vendor-length (1 byte) + value
    // vendor-length includes type and length bytes (so value.len() + 2)
    let vendor_len = value.len() + 2;
    if vendor_len > 255 {
        return Err("vendor attribute value too long".into());
    }
    let mut data = Vec::with_capacity(6 + value.len());
    data.extend_from_slice(&vendor_id.to_be_bytes());
    data.push(vendor_type);
    data.push(vendor_len as u8);
    data.extend_from_slice(value);
    Ok(data)
}

fn encode_value(kind: Option<crate::dictionary::AttrType>, value: &str) -> Result<Vec<u8>> {
    use crate::dictionary::AttrType;
    match kind.unwrap_or(AttrType::String) {
        AttrType::String => Ok(value.as_bytes().to_vec()),
        AttrType::Octets => {
            if let Some(stripped) = value.strip_prefix("0x") {
                hex::decode(stripped).map_err(|e| format!("invalid hex: {e}").into())
            } else {
                Ok(value.as_bytes().to_vec())
            }
        }
        AttrType::Integer => {
            let parsed: u32 = value
                .parse()
                .map_err(|e| format!("invalid integer '{}': {}", value, e))?;
            Ok(parsed.to_be_bytes().to_vec())
        }
        AttrType::IpAddr => {
            let ip: std::net::IpAddr = value
                .parse()
                .map_err(|e| format!("invalid IP address '{}': {}", value, e))?;
            match ip {
                std::net::IpAddr::V4(v4) => Ok(v4.octets().to_vec()),
                std::net::IpAddr::V6(_) => Err("IPv6 not supported for IPv4 attribute".into()),
            }
        }
    }
}

#[derive(Deserialize)]
struct RawUsers {
    #[serde(default)]
    user: Vec<RawUser>,
}

#[derive(Deserialize)]
struct RawUser {
    name: String,
    password: String,
    #[serde(default)]
    reply: Vec<RawReply>,
}

#[derive(Deserialize)]
struct RawReply {
    #[serde(rename = "type")]
    typ: String,
    value: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dictionary::Dictionary;
    use std::fs;

    fn temp_db(contents: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("uradius-userdb-{nonce}.toml"));
        fs::write(&path, contents).expect("write temp db");
        path
    }

    #[test]
    fn loads_users_with_attributes() {
        let path = temp_db(
            r#"
            [[user]]
            name = "alice"
            password = "secret"
            [[user.reply]]
            type = "Filter-Id"
            value = "16384/51200"
            "#,
        );
        let dict = Dictionary::builtin();
        let db = UserDb::load(&path, &dict).expect("db loaded");
        let alice = db.get("alice").expect("user");
        assert_eq!(alice.password, "secret");
        assert_eq!(alice.reply.len(), 1);
        assert_eq!(alice.reply[0].typ, 11); // Filter-Id
        assert_eq!(alice.reply[0].data, b"16384/51200");
    }

    #[test]
    fn verifies_credentials_against_db() {
        let path = temp_db(
            r#"
            [[user]]
            name = "user"
            password = "letmein"
            "#,
        );
        let dict = Dictionary::builtin();
        let db = UserDb::load(&path, &dict).expect("db loaded");

        assert!(verify_credentials("user", b"letmein", &db));
        assert!(!verify_credentials("user", b"wrong", &db));
        assert!(!verify_credentials("missing", b"letmein", &db));
    }

    #[test]
    fn encodes_integer_and_ip_attributes() {
        let reply = vec![
            RawReply {
                typ: "Framed-IP-Address".into(),
                value: "192.168.1.10".into(),
            },
            RawReply {
                typ: "Session-Timeout".into(),
                value: "3600".into(),
            },
        ];
        let dict = Dictionary::builtin();
        let attrs = encode_reply_attrs(&reply, &dict).expect("encode");
        assert_eq!(attrs[0].data, [192, 168, 1, 10]);
        assert_eq!(attrs[1].data, 3600u32.to_be_bytes());
    }

    #[test]
    fn encodes_vendor_specific_attributes() {
        let reply = vec![RawReply {
            typ: "Mikrotik-Rate-Limit".into(),
            value: "10M/20M".into(),
        }];
        let dict = Dictionary::builtin();
        let attrs = encode_reply_attrs(&reply, &dict).expect("encode");
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].typ, 26); // Vendor-Specific
        // Vendor ID 14988 (Mikrotik) = 0x00003A8C
        assert_eq!(&attrs[0].data[0..4], &[0x00, 0x00, 0x3A, 0x8C]);
        // Vendor type 8 (Mikrotik-Rate-Limit)
        assert_eq!(attrs[0].data[4], 8);
        // Vendor length = value len + 2 = 7 + 2 = 9
        assert_eq!(attrs[0].data[5], 9);
        // Value
        assert_eq!(&attrs[0].data[6..], b"10M/20M");
    }

    #[test]
    fn loads_users_with_vendor_attributes() {
        let path = temp_db(
            r#"
            [[user]]
            name = "mikrotik-user"
            password = "test"
            [[user.reply]]
            type = "Mikrotik-Rate-Limit"
            value = "5M/10M"
            "#,
        );
        let dict = Dictionary::builtin();
        let db = UserDb::load(&path, &dict).expect("db loaded");
        let user = db.get("mikrotik-user").expect("user");
        assert_eq!(user.reply.len(), 1);
        assert_eq!(user.reply[0].typ, 26);
    }
}
