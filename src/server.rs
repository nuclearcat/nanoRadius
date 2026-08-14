// Copyright (c) 2025 Denys Fedoryshchenko <denys.f@collabora.com>
// SPDX-License-Identifier: Apache-2.0

use std::io;
use std::net::UdpSocket;
use std::sync::Arc;

use crate::Result;
use crate::SharedState;
use crate::accounting::handle_accounting_packet;
use crate::handle_auth_packet;

/// Bind a UDP socket, reporting the address in the error so a failure at
/// startup names the port that could not be claimed.
pub fn bind_socket(addr: &str) -> Result<UdpSocket> {
    UdpSocket::bind(addr)
        .map_err(|e| io::Error::new(e.kind(), format!("failed to bind {}: {}", addr, e)).into())
}

pub fn run_auth_server(socket: UdpSocket, state: Arc<SharedState>) -> ! {
    state.logger.log(
        "INFO",
        &format!(
            "Auth server listening on {}",
            describe_local_addr(&socket, &state)
        ),
    );
    let mut buffer = [0u8; 4096];
    loop {
        match socket.recv_from(&mut buffer) {
            Ok((size, src)) => {
                let data = &buffer[..size];
                handle_auth_packet(data, src, &socket, &state);
            }
            Err(err) => state
                .logger
                .log("ERROR", &format!("Auth socket error: {err}")),
        }
    }
}

pub fn run_accounting_server(socket: UdpSocket, state: Arc<SharedState>) -> ! {
    state.logger.log(
        "INFO",
        &format!(
            "Accounting server listening on {}",
            describe_local_addr(&socket, &state)
        ),
    );
    let mut buffer = [0u8; 4096];
    loop {
        match socket.recv_from(&mut buffer) {
            Ok((size, src)) => {
                let data = &buffer[..size];
                handle_accounting_packet(
                    data,
                    src,
                    &socket,
                    &state.nas_map,
                    state.debug,
                    state.logger.as_ref(),
                    state.dictionary.as_ref(),
                );
            }
            Err(err) => state
                .logger
                .log("ERROR", &format!("Accounting socket error: {err}")),
        }
    }
}

fn describe_local_addr(socket: &UdpSocket, state: &SharedState) -> String {
    match socket.local_addr() {
        Ok(addr) => addr.to_string(),
        Err(err) => {
            state.logger.log(
                "WARN",
                &format!("Failed to read local socket address: {err}"),
            );
            "<unknown>".to_string()
        }
    }
}
