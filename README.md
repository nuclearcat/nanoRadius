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
userdb = "users"

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

## Integration tests with radclient

After building the release binary and installing `radclient` (package `freeradius-utils` on Debian/Ubuntu), run `scripts/radclient-tests.sh` to exercise PAP, CHAP, and accounting handling using the bundled CI config (`ci-nanoradius.toml`).

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
