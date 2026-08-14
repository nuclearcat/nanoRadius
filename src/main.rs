// Copyright (c) 2025 Denys Fedoryshchenko <denys.f@collabora.com>
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

mod accounting;
mod chap_auth;
mod dictionary;
mod logger;
mod pap_auth;
mod radius;
mod server;
mod user_db;
use chap_auth::verify_chap_password;
use dictionary::Dictionary;
use logger::Logger;
use pap_auth::{
    decrypt_user_password, format_password_debug, has_interior_nul, trim_trailing_zeros,
};
use radius::{RadiusAttribute, RadiusCode, RadiusPacket};
use server::{bind_socket, run_accounting_server, run_auth_server};
use user_db::{UserDb, verify_pap_credentials};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Parser)]
#[command(author, version, about = "Lightweight RADIUS server")]
struct Cli {
    /// Path to the configuration file (nanoradius.toml)
    #[arg(short = 'c', long = "config", default_value = "nanoradius.toml")]
    config: PathBuf,
}

#[derive(Debug, Deserialize)]
struct Config {
    server: ServerConfig,
    nas: NasSection,
}

#[derive(Debug, Deserialize)]
struct ServerConfig {
    listen_auth: String,
    listen_acct: String,
    #[serde(default)]
    debug: bool,
    logfile: Option<String>,
    userdb: String,
    /// Discard Access-Requests that arrive without a Message-Authenticator.
    ///
    /// Defaults to false because older NASes omit the attribute for PAP and
    /// CHAP, but enabling it is what closes CVE-2024-3596 (BlastRADIUS): the
    /// attack rests on forging a response to a request the NAS never
    /// integrity-protected.
    #[serde(default)]
    require_message_authenticator: bool,
}

#[derive(Debug, Deserialize)]
struct NasSection {
    #[serde(default)]
    devices: Vec<NasDeviceConfig>,
}

#[derive(Debug, Deserialize)]
struct NasDeviceConfig {
    ip: String,
    secret: String,
    shortname: Option<String>,
}

#[derive(Debug)]
pub(crate) struct NasDevice {
    pub(crate) secret: String,
    pub(crate) shortname: Option<String>,
}

#[derive(Clone)]
pub(crate) struct SharedState {
    pub(crate) logger: Arc<logger::Logger>,
    pub(crate) debug: bool,
    pub(crate) require_message_authenticator: bool,
    pub(crate) user_db: Arc<UserDb>,
    pub(crate) nas_map: Arc<HashMap<IpAddr, Arc<NasDevice>>>,
    pub(crate) dictionary: Arc<Dictionary>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Fatal error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let config_path = cli.config;
    let config_raw = fs::read_to_string(&config_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("failed to read {}: {}", config_path.display(), e),
        )
    })?;
    let config: Config = toml::from_str(&config_raw)?;
    let config_dir = config_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let logfile_path = config
        .server
        .logfile
        .as_deref()
        .map(|p| resolve_path(&config_dir, p));
    let logger = Arc::new(Logger::new(logfile_path.as_deref())?);
    logger.log("INFO", "Starting nanoRadius server");

    let userdb_path = resolve_path(&config_dir, &config.server.userdb);
    let dictionary_path = resolve_path(&config_dir, "dictionary.toml");
    let dictionary = if dictionary_path.exists() {
        Dictionary::load_from_file(&dictionary_path)?
    } else {
        Dictionary::builtin()
    };
    let dictionary = Arc::new(dictionary);
    let user_db = Arc::new(UserDb::load(&userdb_path, &dictionary)?);
    logger.log(
        "INFO",
        &format!(
            "Loaded {} users from {}",
            user_db.user_count(),
            userdb_path.display()
        ),
    );

    let nas_map = Arc::new(build_nas_map(&config.nas.devices)?);
    if nas_map.is_empty() {
        return Err("no NAS devices configured".into());
    }

    let state = Arc::new(SharedState {
        logger: logger.clone(),
        debug: config.server.debug,
        require_message_authenticator: config.server.require_message_authenticator,
        user_db,
        nas_map,
        dictionary,
    });

    // Bind both sockets before serving anything: a listener that cannot claim
    // its port is a fatal misconfiguration, not something to run without.
    let auth_socket = bind_socket(&config.server.listen_auth)?;
    let acct_socket = bind_socket(&config.server.listen_acct)?;

    let acct_state = state.clone();
    thread::spawn(move || run_accounting_server(acct_socket, acct_state));

    run_auth_server(auth_socket, state)
}

fn resolve_path(base: &Path, value: &str) -> PathBuf {
    let candidate = Path::new(value);
    if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        base.join(candidate)
    }
}

fn build_nas_map(devices: &[NasDeviceConfig]) -> Result<HashMap<IpAddr, Arc<NasDevice>>> {
    let mut map = HashMap::new();
    for device in devices {
        let ip: IpAddr = device.ip.parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid NAS IP {}: {}", device.ip, e),
            )
        })?;
        let entry = NasDevice {
            secret: device.secret.clone(),
            shortname: device.shortname.clone(),
        };
        map.insert(ip, Arc::new(entry));
    }
    Ok(map)
}

pub(crate) fn handle_auth_packet(
    data: &[u8],
    src: SocketAddr,
    socket: &UdpSocket,
    state: &Arc<SharedState>,
) {
    let Some(nas) = state.nas_map.get(&src.ip()).cloned() else {
        state.logger.log(
            "WARN",
            &format!("Auth request from unknown NAS {}", src.ip()),
        );
        return;
    };

    let packet = match RadiusPacket::parse(data) {
        Ok(packet) => packet,
        Err(err) => {
            state
                .logger
                .log("WARN", &format!("Invalid auth packet: {err}"));
            return;
        }
    };

    match RadiusPacket::verify_message_authenticator(data, &nas.secret) {
        Ok(Some(false)) => {
            state.logger.log(
                "WARN",
                &format!("Bad Message-Authenticator from {}", src.ip()),
            );
            return;
        }
        Ok(None) if state.require_message_authenticator => {
            state.logger.log(
                "WARN",
                &format!(
                    "Discarding Access-Request from {} with no Message-Authenticator \
                     (require_message_authenticator = true)",
                    src.ip()
                ),
            );
            return;
        }
        Ok(_) => {}
        Err(err) => {
            state.logger.log(
                "WARN",
                &format!("Failed to verify Message-Authenticator: {err}"),
            );
            return;
        }
    }

    if packet.code != RadiusCode::AccessRequest as u8 {
        state.logger.log(
            "WARN",
            &format!("Unsupported auth code {} from {}", packet.code, src),
        );
        return;
    }

    let username = match packet
        .attribute_value(1)
        .and_then(|v| String::from_utf8(v.to_vec()).ok())
    {
        Some(name) => name,
        None => {
            state.logger.log("WARN", "Auth request missing User-Name");
            send_access_response(
                RadiusCode::AccessReject,
                &packet,
                &nas.secret,
                socket,
                src,
                state,
                &[],
            );
            return;
        }
    };

    let mut reason = String::from("credentials valid");
    let auth_result = if let Some(encrypted) = packet.attribute_value(2) {
        match decrypt_user_password(encrypted, &nas.secret, &packet.authenticator) {
            Ok(password) => {
                if state.debug {
                    let preview = format_password_debug(trim_trailing_zeros(&password));
                    state.logger.debug(
                        true,
                        &format!("PAP password for {} = {}", username, preview),
                    );
                }
                if has_interior_nul(&password) {
                    state.logger.log(
                        "WARN",
                        &format!(
                            "Decrypted PAP payload for {} from {} contains interior NUL byte(s) \
                             (likely wrong shared secret or malformed client)",
                            username,
                            src.ip()
                        ),
                    );
                }
                if verify_pap_credentials(&username, &password, &state.user_db) {
                    true
                } else {
                    reason = "invalid username/password".into();
                    false
                }
            }
            Err(err) => {
                reason = format!("PAP decrypt error: {err}");
                state.logger.log(
                    "WARN",
                    &format!("Failed to decrypt PAP password for {}: {}", username, err),
                );
                false
            }
        }
    } else if let Some(chap_payload) = packet.attribute_value(3) {
        if verify_chap_password(
            &username,
            chap_payload,
            packet.attribute_value(60).unwrap_or(&packet.authenticator),
            &state.user_db,
        ) {
            true
        } else {
            reason = "CHAP validation failed".into();
            false
        }
    } else {
        reason = "missing credentials".into();
        state.logger.log(
            "WARN",
            &format!("Auth request for {} missing credentials", username),
        );
        false
    };

    log_auth_decision(state, &nas, src, &username, auth_result, &reason);
    let reply_attrs: &[RadiusAttribute] = if auth_result {
        state
            .user_db
            .get(&username)
            .map(|u| u.reply.as_slice())
            .unwrap_or(&[])
    } else {
        &[]
    };
    let response_code = if auth_result {
        RadiusCode::AccessAccept
    } else {
        RadiusCode::AccessReject
    };
    send_access_response(
        response_code,
        &packet,
        &nas.secret,
        socket,
        src,
        state,
        reply_attrs,
    );
}

fn send_access_response(
    code: RadiusCode,
    request: &RadiusPacket,
    secret: &str,
    socket: &UdpSocket,
    dest: SocketAddr,
    state: &Arc<SharedState>,
    attributes: &[RadiusAttribute],
) {
    // Proxy-State from the request is appended to every reply, accept or
    // reject, so a proxy in front of us can route the response (RFC 2865 5.33).
    let attributes = request.reply_attributes(attributes);
    match RadiusPacket::build_response(code, request, secret, &attributes) {
        Ok(response) => {
            if let Err(err) = socket.send_to(&response, dest) {
                state
                    .logger
                    .log("ERROR", &format!("Failed to send auth response: {err}"));
            }
        }
        Err(err) => state
            .logger
            .log("ERROR", &format!("Failed to build auth response: {err}")),
    }
}

fn log_auth_decision(
    state: &SharedState,
    nas: &NasDevice,
    src: SocketAddr,
    username: &str,
    success: bool,
    reason: &str,
) {
    let outcome = if success { "ACCEPT" } else { "REJECT" };
    state.logger.log(
        "INFO",
        &format!(
            "[AUTH {}] user={} nas={} ip={} reason={}",
            outcome,
            username,
            nas.shortname
                .clone()
                .unwrap_or_else(|| "unknown".to_string()),
            src.ip(),
            reason
        ),
    );
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::collections::HashMap;
    use std::io;
    use std::time::Duration;

    #[test]
    fn sends_mikrotik_reply_attributes() -> Result<()> {
        let dictionary = Dictionary::builtin();
        let users_path = {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let mut path = std::env::temp_dir();
            path.push(format!("nanoradius-users-{nanos}.toml"));
            let content = r#"
[[user]]
name = "mikrotik-user"
password = "secret"
[[user.reply]]
type = "Mikrotik-Rate-Limit"
value = "5M/10M"
"#;
            std::fs::write(&path, content)?;
            path
        };

        let user_db = Arc::new(UserDb::load(&users_path, &dictionary)?);
        let state = Arc::new(SharedState {
            logger: Arc::new(Logger::new(None)?),
            debug: false,
            require_message_authenticator: false,
            user_db,
            nas_map: Arc::new(HashMap::new()),
            dictionary: Arc::new(dictionary),
        });

        let server_socket = match UdpSocket::bind("127.0.0.1:0") {
            Ok(sock) => sock,
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping Mikrotik reply test: {}", err);
                return Ok(());
            }
            Err(err) => return Err(err.into()),
        };
        let client_socket = match UdpSocket::bind("127.0.0.1:0") {
            Ok(sock) => sock,
            Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping Mikrotik reply test: {}", err);
                return Ok(());
            }
            Err(err) => return Err(err.into()),
        };
        client_socket.set_read_timeout(Some(Duration::from_millis(500)))?;
        let dest = client_socket.local_addr()?;

        let mut request_bytes = vec![0u8; 20];
        request_bytes[0] = RadiusCode::AccessRequest as u8;
        request_bytes[1] = 42;
        request_bytes[2..4].copy_from_slice(&(20u16).to_be_bytes());
        let request = RadiusPacket::parse(&request_bytes)?;

        let user = state.user_db.get("mikrotik-user").expect("user present");
        send_access_response(
            RadiusCode::AccessAccept,
            &request,
            "testing123",
            &server_socket,
            dest,
            &state,
            &user.reply,
        );

        let mut buf = [0u8; 1024];
        let (size, _) = client_socket.recv_from(&mut buf)?;
        let response = RadiusPacket::parse(&buf[..size])?;

        let vsa = response
            .attributes
            .iter()
            .find(|a| a.typ == 26)
            .expect("Vendor-Specific attribute present");
        assert!(vsa.data.len() >= 7);
        assert_eq!(
            u32::from_be_bytes([vsa.data[0], vsa.data[1], vsa.data[2], vsa.data[3]]),
            14988
        );
        assert_eq!(vsa.data[4], 8); // Mikrotik-Rate-Limit
        assert_eq!(&vsa.data[6..], b"5M/10M");

        Ok(())
    }
}
