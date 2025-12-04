use std::collections::HashMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::radius::RadiusAttribute;
use crate::Result;

#[derive(Deserialize)]
struct RawDictionary {
    #[serde(default)]
    attributes: HashMap<String, RawAttribute>,
}

#[derive(Deserialize)]
struct RawAttribute {
    name: String,
    #[serde(default)]
    r#type: Option<String>,
    #[serde(default)]
    enums: HashMap<String, String>,
}

#[derive(Clone)]
pub struct AttributeMeta {
    name: String,
    enums: HashMap<u32, String>,
    pub kind: AttrType,
}

#[derive(Clone)]
pub struct Dictionary {
    attrs: HashMap<u8, AttributeMeta>,
    names: HashMap<String, u8>,
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

    pub fn describe_attributes(&self, attributes: &[RadiusAttribute]) -> String {
        attributes
            .iter()
            .map(|attr| {
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
                    (None, Err(_)) => format!("type {} len {} ({:02x?})", attr.typ, attr.data.len(), attr.data),
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
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
        Self { attrs, names }
    }
}

fn parse_integer(value: &[u8]) -> Option<u32> {
    if value.len() == 4 {
        Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]))
    } else {
        None
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
