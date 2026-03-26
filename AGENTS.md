# AGENTS.md

## Project at a glance

- `nanoproxy.go` is the composition root: it parses env config, wires shared dependencies, and starts two servers in
  parallel.
- Runtime has two protocol frontends sharing core services:
    - SOCKS5 server (`pkg/socks5`) on `ADDR` (default `:1080`).
    - HTTP proxy server (`pkg/httpproxy`) on `ADDR_HTTP` (default `:8080`).
- Both frontends reuse the same credential store and resolver instance, so auth and DNS behavior should stay aligned
  across protocols.

## Key architecture and data flow

- Config is env-driven via struct tags in `pkg/config/config.go` (`caarlos0/env/v10`), not via JSON/YAML files.
- User credentials are managed through the Admin Console and stored in `USER_STORE_PATH` (BoltDB). Credentials are
  validated with bcrypt in `pkg/credential/credentials.go`.
- SOCKS5 flow (`pkg/socks5/socks5.go`): handshake -> auth negotiation -> request parse (`pkg/socks5/request.go`) ->
  optional DNS resolve -> relay.
- HTTP flow (`pkg/httpproxy/httpproxy.go`): `ServeHTTP` dispatches `CONNECT` vs normal HTTP; hop-by-hop headers are
  stripped before forwarding.
- Tor mode (`TOR_ENABLED=true`) swaps dialers for both frontends (`pkg/tor/dial.go`) and runs identity switching (
  `pkg/tor/identity.go`).

## Integration points and external assumptions

- Tor integration expects local Tor endpoints: SOCKS on `localhost:9050`, control port on `127.0.0.1:9051` (
  `pkg/tor/controller.go`).
- `Dockerfile-tor` + `supervisord.conf` run both Tor and NanoProxy in one container; this is the intended Tor deployment
  path.
- System package/service deployment uses `systemd/nanoproxy.service` with inline `Environment=` values and optional
  systemd drop-ins for overrides.

## Developer workflows that matter here

- Run all tests:
    - `go test ./...`
- Coverage with repository thresholds (file/package 60%, total 80%):
    - `make check-coverage`
- Coverage profile only:
    - `make coverage-only`
- Release snapshot build (requires GoReleaser):
    - `make build_snapshot`

## Project-specific coding/testing conventions

- Prefer dependency injection via `Config` fields (`Dial`, `Resolver`, `Logger`) for testability (see
  `pkg/httpproxy/httpproxy.go`, `pkg/socks5/socks5.go`).
- For SOCKS5 protocol changes, keep wire-format behavior covered with byte-level tests (see
  `pkg/socks5/socks5_test.go`).
- HTTP proxy tests commonly use `httptest.NewServer` and custom mock `net.Conn`/`Hijacker` types (
  `pkg/httpproxy/httpproxy_test.go`).
- Keep auth behavior consistent across protocols: HTTP expects `Proxy-Authorization` Basic, SOCKS5 uses RFC1929
  username/password.
- Preserve structured logging style (`zerolog` fields like `client_addr`, `dest_addr`, `latency`) when adding new
  request paths.

