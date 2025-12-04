// Copyright (c) 2025 Denys Fedoryshchenko <denys.f@collabora.com>
// SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-Proprietary

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::Result;
use crate::radius::RadiusAttribute;

#[derive(Deserialize)]
struct RawDictionary {
    #[serde(default)]
    attributes: HashMap<String, RawAttribute>,
    #[serde(default)]
    vendors: HashMap<String, RawVendor>,
}

#[derive(Deserialize)]
struct RawAttribute {
    name: String,
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    enums: HashMap<String, String>,
}

#[derive(Deserialize)]
struct RawVendor {
    name: String,
    #[serde(default)]
    attributes: HashMap<String, RawAttribute>,
}

#[derive(Clone)]
pub struct AttributeMeta {
    name: String,
    enums: HashMap<u32, String>,
    pub kind: AttrType,
}

#[derive(Clone)]
pub struct VendorAttributeMeta {
    pub name: String,
    pub kind: AttrType,
}

#[derive(Clone)]
pub struct VendorMeta {
    pub name: String,
    pub attrs: HashMap<u8, VendorAttributeMeta>,
    names: HashMap<String, u8>,
}

#[derive(Clone)]
pub struct Dictionary {
    attrs: HashMap<u8, AttributeMeta>,
    names: HashMap<String, u8>,
    vendors: HashMap<u32, VendorMeta>,
}

#[derive(Clone, Copy)]
pub enum AttrType {
    String,
    Octets,
    Integer,
    IpAddr,
}

impl Dictionary {
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        let raw: RawDictionary = toml::from_str(&contents)?;
        Ok(Self::from_raw(raw))
    }

    pub fn builtin() -> Self {
        let raw: RawDictionary =
            toml::from_str(include_str!("../dictionary.toml")).expect("builtin dictionary parses");
        Self::from_raw(raw)
    }

    pub fn code_for_name(&self, name: &str) -> Option<u8> {
        self.names.get(&name.to_ascii_lowercase()).copied()
    }

    pub fn meta(&self, code: u8) -> Option<&AttributeMeta> {
        self.attrs.get(&code)
    }

    pub fn lookup_vendor_attr(&self, name: &str) -> Option<(u32, u8, &VendorAttributeMeta)> {
        // Look for "Vendor-Attr" format (e.g., "Mikrotik-Rate-Limit")
        for (vendor_id, vendor) in &self.vendors {
            if let Some(code) = vendor.names.get(&name.to_ascii_lowercase()) {
                if let Some(meta) = vendor.attrs.get(code) {
                    return Some((*vendor_id, *code, meta));
                }
            }
        }
        None
    }

    pub fn describe_attributes(&self, attributes: &[RadiusAttribute]) -> String {
        attributes
            .iter()
            .map(|attr| {
                // Handle Vendor-Specific attributes (type 26)
                if attr.typ == 26 && attr.data.len() >= 6 {
                    return self.describe_vsa(&attr.data);
                }
                let name = self.attrs.get(&attr.typ).map(|m| m.name.as_str());
                if let Some(meta) = self.attrs.get(&attr.typ) {
                    if let Some(value) =
                        parse_integer(&attr.data).and_then(|v| meta.enums.get(&v).map(|l| (v, l)))
                    {
                        return format!("{}={} ({})", meta.name, value.1, value.0);
                    }
                }
                match (name, String::from_utf8(attr.data.clone())) {
                    (Some(name), Ok(text)) => format!("{}='{}'", name, text),
                    (Some(name), Err(_)) => {
                        format!("{} len {} ({:02x?})", name, attr.data.len(), attr.data)
                    }
                    (None, Ok(text)) => format!("type {}='{}'", attr.typ, text),
                    (None, Err(_)) => format!(
                        "type {} len {} ({:02x?})",
                        attr.typ,
                        attr.data.len(),
                        attr.data
                    ),
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    fn describe_vsa(&self, data: &[u8]) -> String {
        if data.len() < 6 {
            return format!("Vendor-Specific (malformed, len {})", data.len());
        }
        let vendor_id = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let vendor_type = data[4];
        let vendor_len = data[5] as usize;
        if vendor_len < 2 || data.len() < 4 + vendor_len {
            return format!("Vendor-Specific (vendor={}, malformed)", vendor_id);
        }
        let value = &data[6..4 + vendor_len];

        if let Some(vendor) = self.vendors.get(&vendor_id) {
            if let Some(attr_meta) = vendor.attrs.get(&vendor_type) {
                match String::from_utf8(value.to_vec()) {
                    Ok(text) => return format!("{}='{}'", attr_meta.name, text),
                    Err(_) => return format!("{} ({:02x?})", attr_meta.name, value),
                }
            }
            match String::from_utf8(value.to_vec()) {
                Ok(text) => return format!("{}-Unknown-{}='{}'", vendor.name, vendor_type, text),
                Err(_) => {
                    return format!("{}-Unknown-{} ({:02x?})", vendor.name, vendor_type, value);
                }
            }
        }

        match String::from_utf8(value.to_vec()) {
            Ok(text) => format!("Vendor-{}-Attr-{}='{}'", vendor_id, vendor_type, text),
            Err(_) => format!("Vendor-{}-Attr-{} ({:02x?})", vendor_id, vendor_type, value),
        }
    }

    pub fn acct_status_label(&self, value: u32) -> Option<&str> {
        self.attrs
            .get(&40)
            .and_then(|meta| meta.enums.get(&value).map(|s| s.as_str()))
    }

    fn from_raw(raw: RawDictionary) -> Self {
        let mut attrs = HashMap::new();
        let mut names = HashMap::new();
        for (code_str, raw_attr) in raw.attributes {
            let code: u8 = code_str.parse().expect("attribute code must be u8");
            let enums = raw_attr
                .enums
                .into_iter()
                .map(|(k, v)| {
                    let parsed: u32 = k.parse().expect("enum key must be u32");
                    (parsed, v)
                })
                .collect();
            names.insert(raw_attr.name.to_ascii_lowercase(), code);
            attrs.insert(
                code,
                AttributeMeta {
                    name: raw_attr.name,
                    enums,
                    kind: parse_kind(raw_attr.r#type.as_deref()),
                },
            );
        }

        let mut vendors = HashMap::new();
        for (vendor_id_str, raw_vendor) in raw.vendors {
            let vendor_id: u32 = vendor_id_str.parse().expect("vendor ID must be u32");
            let mut vendor_attrs = HashMap::new();
            let mut vendor_attr_names = HashMap::new();
            for (attr_code_str, raw_attr) in raw_vendor.attributes {
                let attr_code: u8 = attr_code_str
                    .parse()
                    .expect("vendor attribute code must be u8");
                vendor_attr_names.insert(raw_attr.name.to_ascii_lowercase(), attr_code);
                vendor_attrs.insert(
                    attr_code,
                    VendorAttributeMeta {
                        name: raw_attr.name,
                        kind: parse_kind(raw_attr.r#type.as_deref()),
                    },
                );
            }
            vendors.insert(
                vendor_id,
                VendorMeta {
                    name: raw_vendor.name,
                    attrs: vendor_attrs,
                    names: vendor_attr_names,
                },
            );
        }

        Self {
            attrs,
            names,
            vendors,
        }
    }
}

fn parse_integer(value: &[u8]) -> Option<u32> {
    if value.len() == 4 {
        Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_mikrotik_vsa() {
        let dict = Dictionary::builtin();
        let vsa = RadiusAttribute {
            typ: 26,
            data: vec![
                0x00, 0x00, 0x3A, 0x8C, // Vendor ID 14988
                8,    // vendor type (Mikrotik-Rate-Limit)
                8,    // vendor length (value len + 2)
                b'5', b'M', b'/', b'1', b'0', b'M',
            ],
        };
        let desc = dict.describe_attributes(&[vsa]);
        assert_eq!(desc, "Mikrotik-Rate-Limit='5M/10M'");
    }
}

fn parse_kind(raw: Option<&str>) -> AttrType {
    match raw.map(|s| s.to_ascii_lowercase()) {
        Some(ref t) if t == "octets" || t == "bytes" => AttrType::Octets,
        Some(ref t) if t == "integer" || t == "int" || t == "u32" => AttrType::Integer,
        Some(ref t) if t == "ipaddr" || t == "ipv4" => AttrType::IpAddr,
        Some(_) => AttrType::String,
        None => AttrType::String,
    }
}
