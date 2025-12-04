# nanoRadius

Lightweight authentication and accounting server.

## Build

```bash
cargo build --release
```

Binary will be at `./target/release/nanoRadius`

## Configuration

Create `uradius.toml`:

```toml
[server]
listen_auth = "0.0.0.0:1812"
listen_acct = "0.0.0.0:1813"
debug = true
logfile = "uradius.log"
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
```

## Run

```bash
./target/release/nanoRadius -c uradius.toml
```

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
