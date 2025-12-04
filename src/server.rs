// Copyright (c) 2025 Denys Fedoryshchenko <denys.f@collabora.com>
// SPDX-License-Identifier: GPL-3.0-or-later OR LicenseRef-Proprietary

use std::net::UdpSocket;
use std::sync::Arc;

use crate::Result;
use crate::SharedState;
use crate::accounting::handle_accounting_packet;
use crate::handle_auth_packet;

pub fn run_auth_server(addr: &str, state: Arc<SharedState>) -> Result<()> {
    let socket = UdpSocket::bind(addr)?;
    state
        .logger
        .log("INFO", &format!("Auth server listening on {}", addr));
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

pub fn run_accounting_server(addr: &str, state: Arc<SharedState>) -> Result<()> {
    let socket = UdpSocket::bind(addr)?;
    state
        .logger
        .log("INFO", &format!("Accounting server listening on {}", addr));
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
