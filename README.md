# nanoRadius

Lightweight authentication and accounting server.

## Build

```bash
cargo build --release
```

Binary will be at `./target/release/nanoRadius`

## Configuration

Create `nanoradius.toml`:

```toml
[server]
listen_auth = "0.0.0.0:1812"
listen_acct = "0.0.0.0:1813"
debug = true
logfile = "nanoradius.log"
userdb = "users.toml"
# Discard Access-Requests that arrive without a Message-Authenticator.
# Defaults to false; see "Hardening" below.
require_message_authenticator = false

[nas]
[[nas.devices]]
ip = "127.0.0.1"
secret = "testing123"
shortname = "localnas"
```

Create `users.toml`:

```toml
[[user]]
name = "alice"
password = "secret"

[[user]]
name = "bob"
password = "pass123"

# User with custom reply attributes
[[user]]
name = "charlie"
password = "mypass"
[[user.reply]]
type = "Framed-IP-Address"
value = "192.168.1.100"
[[user.reply]]
type = "Session-Timeout"
value = "3600"
[[user.reply]]
type = "Filter-Id"
value = "premium-user"

# User with vendor-specific attributes (Mikrotik)
[[user]]
name = "mikrotik-user"
password = "secret123"
[[user.reply]]
type = "Mikrotik-Rate-Limit"
value = "10M/20M"
[[user.reply]]
type = "Mikrotik-Address-List"
value = "allowed-users"
```

## Run

```bash
./target/release/nanoRadius -c nanoradius.toml
```

## Docker

Image is published to `ghcr.io/nuclearcat/nanoradius`.

Default config path: `/etc/nanoradius/nanoradius.toml`  
Default log path: `/var/log/nanoradius/nanoradius.log`

```bash
docker run --rm -p 1812:1812/udp -p 1813:1813/udp ghcr.io/nuclearcat/nanoradius
```

The bundled `/etc/nanoradius/nanoradius.toml` and `users.toml` are a demo
configuration with published users and the shared secret `testing123`. Mount
your own over them before exposing the container to anything:

```bash
docker run --rm -p 1812:1812/udp -p 1813:1813/udp \
  -v /path/to/nanoradius.toml:/etc/nanoradius/nanoradius.toml:ro \
  -v /path/to/users.toml:/etc/nanoradius/users.toml:ro \
  ghcr.io/nuclearcat/nanoradius
```

## Integration tests with radclient

After building the release binary and installing `radclient` (package `freeradius-utils` on Debian/Ubuntu), run `scripts/radclient-tests.sh` to exercise PAP, CHAP, and accounting handling using the bundled CI config (`ci-nanoradius.toml`).

## Hardening

**`require_message_authenticator`**

RADIUS over UDP authenticates a response with an MD5 digest, which CVE-2024-3596
(BlastRADIUS) shows can be forged by an attacker able to modify traffic between
the NAS and the server. The defence is the Message-Authenticator attribute
(RFC 3579), an HMAC-MD5 over the whole packet.

nanoRadius always validates a Message-Authenticator when one is present, and
always includes one in its reply when the request carried one. Setting
`require_message_authenticator = true` additionally discards any Access-Request
that arrives without one, which closes the attack.

It defaults to `false` because older NASes omit the attribute for PAP and CHAP.
Turn it on once you have confirmed every configured NAS sends one — a rejected
request is logged as:

```
[WARN] Discarding Access-Request from 10.0.0.1 with no Message-Authenticator
```

**`debug`**

`debug = true` writes decrypted PAP passwords to the log in cleartext. Use it
only when diagnosing an authentication problem, and treat the resulting log file
as a credential store.

## Troubleshooting

**Port already in use**
```
Error: Address already in use
```
Another service is using port 1812 or 1813. Stop the conflicting service or change ports in config.

**Permission denied on ports**
```
Error: Permission denied
```
Ports below 1024 require root. Either run with `sudo` or use higher port numbers.

**Authentication failing**
- Verify the client IP matches an entry in `[[nas.devices]]`
- Check the shared secret matches on both sides
- Ensure username/password exists in `users.toml`

**No log output**
- Set `debug = true` in config
- Check `logfile` path is writable
