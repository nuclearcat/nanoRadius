# TODO

Findings from a code review of the tree at `fcb2a7f`. Each bug was reproduced
against a running server unless noted otherwise.

## Bugs

All fixed. Each is covered by unit tests and was re-checked against a running
server.

- [x] **Accounting server bind failure was not fatal** (`f0ef8a1`). d9e5418
  covered only the auth server; the accounting socket was bound inside the
  spawned thread, so a failure left the process running with accounting
  silently dead. Both sockets are now bound in `run()` before serving starts.
- [x] **Proxy-State was not echoed** (`f35b46e`). RFC 2865 5.33 and RFC 2866
  4.1 require returning it unmodified and in order; we returned none. Now
  appended on all four reply paths.
- [x] **Message-Authenticator was never added to responses** (`6175ba4`).
  RFC 3579 3.2 requires one whenever the request carried one.
- [x] **No way to require a Message-Authenticator** (`ca888de`). Added
  `require_message_authenticator`, which is what closes CVE-2024-3596
  (BlastRADIUS). Defaults to false; documented in the README.
- [x] **Trailing padding was rejected** (`98f545c`). RFC 2865 3 requires octets
  past Length to be ignored; we demanded an exact match and dropped the packet.
- [x] **Malformed `dictionary.toml` panicked the server** (`53cdec3`). Four
  `.expect()` calls on user input, now startup errors naming the bad key.
- [x] **Container image shipped `debug = true`** (`b4f52ac`), writing cleartext
  PAP passwords to the log.

## Hardening

Not yet done. Line references are to `fcb2a7f` and have shifted since.

- **PAP wins over CHAP when both are present** (`src/main.rs:257-306`). RFC 2865
  says an Access-Request must not contain both; a valid CHAP-Password is
  currently ignored in favour of a wrong User-Password. Reject as malformed.
- **No 128-byte cap on User-Password** (`src/pap_auth.rs:15-18`). RFC 2865
  section 5.2 caps it at 128 octets; a 240-byte attribute is accepted and
  decrypted.
- **Duplicate attributes: first one wins** (`src/radius.rs:56`). Two User-Name
  attributes `[bob, alice]` with bob's password yields an Accept for bob. Not
  exploitable given the shared-secret check, but single-instance attributes
  appearing more than once should be rejected.
- **Duplicate usernames silently overwrite** (`src/user_db.rs:42`). Warn on a
  shadowed entry.
- **Response size not capped at 4096** (`src/radius.rs:75`). Checked against
  `u16::MAX`; enough reply attributes builds a packet NASes will drop.
- **Dead check** (`src/accounting.rs:104`). `data.len() < packet.length` can
  never be true, since `parse` already enforced equality.
- **Dead function** in `scripts/radclient-tests.sh`. `wait_for_port` uses
  `socket.create_connection` (TCP) against a UDP port and is never called.
- ~~**README says `userdb = "users"`**~~. Fixed in `ca888de`.
- **CI lint is red on current stable.** `cargo fmt --check` and `cargo clippy`
  both fail at `fcb2a7f` on rustfmt/clippy 1.9.0: one import in `src/main.rs`
  needs rewrapping, and there are four `collapsible_if` warnings in
  `src/dictionary.rs` and `src/logger.rs`. Toolchain drift, not new code —
  worth a standalone cleanup commit since `lint.yml` runs with `-D warnings`.

## Unimplemented features

Roughly by impact.

- **Accounting is log-only.** `handle_accounting_packet` prints a line and
  discards the packet: no session table, no Acct-Session-Time accumulation, no
  persistence, no way to answer "who is online". Start, Stop and Interim-Update
  are all treated identically.
- **No CoA / Disconnect-Request (RFC 5176).** `doc/rfc5176.txt` is bundled, but
  nothing listens on 3799 and there is no packet type for it.
- **No EAP, MS-CHAP or MS-CHAPv2**, and no Access-Challenge / State machinery,
  so no multi-round authentication of any kind. PAP and CHAP are the whole
  surface.
- **Cleartext passwords only.** CHAP requires it, but PAP-only users have no
  hashed-password option.
- **No config or user-DB reload.** No SIGHUP handler; every user change needs a
  restart.
- **NAS matching is exact-IP only.** No CIDR ranges, no default/wildcard client,
  no NAS-Identifier-based lookup.
- **No `Reply-Message` on reject.** Clients get no reason string.
- **No IPv6 attributes.** `encode_value` explicitly errors on IPv6
  (`src/user_db.rs:166`); no Framed-IPv6-* support.
- **Dictionary path is hardcoded** to `<config_dir>/dictionary.toml`
  (`src/main.rs:115`). Not settable in config, and the Docker image does not
  ship one, so the built-in is always used there.
- **Single-threaded per socket.** One blocking `recv_from` loop each, with log
  writes under a mutex on the packet path. No worker pool, no rate limiting.
- **No log rotation or syslog.** The file grows unbounded, and `println!` on the
  packet path panics if stdout is closed.
