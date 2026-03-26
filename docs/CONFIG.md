# NanoProxy Configuration

NanoProxy is configured entirely through environment variables. There is no configuration file needed.

## Environment Variables Reference

### Network Configuration

| Variable     | Type   | Default | Description                                            |
|--------------|--------|---------|--------------------------------------------------------|
| `NETWORK`    | string | `tcp`   | Network protocol for listening (`tcp`, `tcp4`, `tcp6`) |
| `ADDR`       | string | `:1080` | SOCKS5 server listen address (host:port)               |
| `ADDR_HTTP`  | string | `:8080` | HTTP proxy server listen address (host:port)           |
| `ADDR_ADMIN` | string | `:9090` | Admin panel listen address (host:port)                 |

### Timeout Configuration

| Variable         | Type     | Default | Description                                      |
|------------------|----------|---------|--------------------------------------------------|
| `CLIENT_TIMEOUT` | duration | `15s`   | Client connection timeout (read/write deadlines) |
| `DEST_TIMEOUT`   | duration | `15s`   | Destination connection timeout                   |

### Logging Configuration

| Variable    | Type   | Default | Description                                                     |
|-------------|--------|---------|-----------------------------------------------------------------|
| `LOG_LEVEL` | string | `info`  | Log level: `debug`, `info`, `warn`, `error`                     |
| `TZ`        | string | `Local` | Timezone for logging timestamps (IANA timezone name or `Local`) |

### User Storage Configuration

| Variable          | Type   | Default             | Description                                                              |
|-------------------|--------|---------------------|--------------------------------------------------------------------------|
| `USER_STORE_PATH` | string | `nanoproxy-data.db` | Path to BoltDB database for persistent user storage and traffic tracking |

### Admin Panel Configuration

| Variable                   | Type         | Default | Description                                                                                      |
|----------------------------|--------------|---------|--------------------------------------------------------------------------------------------------|
| `ADMIN_COOKIE_SECURE`      | bool         | `false` | Enable secure cookie flag for HTTPS deployments (`true`/`false`)                                 |
| `ADMIN_MAX_LOGIN_ATTEMPTS` | int          | `5`     | Maximum failed login attempts before account lockout                                             |
| `ADMIN_LOGIN_WINDOW`       | duration     | `5m`    | Time window for tracking failed login attempts                                                   |
| `ADMIN_LOCKOUT_DURATION`   | duration     | `10m`   | Duration to lock account after max failed attempts                                               |
| `ADMIN_ALLOWED_ORIGINS`    | string (csv) | empty   | Comma-separated list of allowed CORS origins for admin panel (e.g., `https://admin.example.com`) |

### Tor Integration

| Variable                | Type     | Default | Description                                                    |
|-------------------------|----------|---------|----------------------------------------------------------------|
| `TOR_ENABLED`           | bool     | `false` | Enable Tor integration for anonymous proxying (`true`/`false`) |
| `TOR_IDENTITY_INTERVAL` | duration | `10m`   | Interval for switching Tor exit node identity                  |

## Configuration Examples

### Basic SOCKS5 + HTTP Proxy (No Auth)

```bash
ADDR=:1080
ADDR_HTTP=:8080
LOG_LEVEL=info
```

### Basic Setup with User Storage

```bash
ADDR=:1080
ADDR_HTTP=:8080
ADDR_ADMIN=:9090
USER_STORE_PATH=/var/lib/nanoproxy/data.db
LOG_LEVEL=info
```

Then access the admin console to create users.

### Production Deployment

```bash
NETWORK=tcp
ADDR=0.0.0.0:1080
ADDR_HTTP=0.0.0.0:8080
ADDR_ADMIN=127.0.0.1:9090
LOG_LEVEL=warn
CLIENT_TIMEOUT=30s
DEST_TIMEOUT=30s
USER_STORE_PATH=/var/lib/nanoproxy/data.db
ADMIN_COOKIE_SECURE=true
ADMIN_ALLOWED_ORIGINS=https://admin.example.com
```

### Tor Mode (Anonymized)

```bash
ADDR=:1080
ADDR_HTTP=:8080
TOR_ENABLED=true
TOR_IDENTITY_INTERVAL=5m
LOG_LEVEL=info
```

### Debug Mode (Development)

```bash
ADDR=127.0.0.1:1080
ADDR_HTTP=127.0.0.1:8080
LOG_LEVEL=debug
CLIENT_TIMEOUT=60s
DEST_TIMEOUT=60s
```

## Duration Format

Durations use Go duration syntax:

- `s` = seconds (e.g., `5s`)
- `m` = minutes (e.g., `5m`)
- `h` = hours (e.g., `1h`)

Examples: `15s`, `5m`, `1h30m`

## Timezone Format

Use IANA timezone names (e.g., `America/New_York`, `Europe/London`, `Asia/Tokyo`) or `Local` for system timezone.

## Log Levels

- `debug` - Detailed debug information (request completion, connection details)
- `info` - General informational messages (server startup, important events)
- `warn` - Warning messages (non-critical issues)
- `error` - Error messages only (authentication failures, connection errors, etc.)

## Docker/Compose Example

```yaml
version: '3.8'
services:
  nanoproxy:
    image: nanoproxy:latest
    ports:
      - "1080:1080"
      - "8080:8080"
      - "9090:9090"
    environment:
      ADDR: 0.0.0.0:1080
      ADDR_HTTP: 0.0.0.0:8080
      ADDR_ADMIN: 0.0.0.0:9090
      LOG_LEVEL: info
      USER_STORE_PATH: /data/nanoproxy.db
      ADMIN_COOKIE_SECURE: "true"
    volumes:
      - nanoproxy_data:/data

volumes:
  nanoproxy_data:
```

## Systemd Service Example

```ini
[Unit]
Description=NanoProxy
After=network.target

[Service]
Type=simple
User=nanoproxy
WorkingDirectory=/opt/nanoproxy
ExecStart=/opt/nanoproxy/nanoproxy
Restart=on-failure
RestartSec=10s

Environment="ADDR=0.0.0.0:1080"
Environment="ADDR_HTTP=0.0.0.0:8080"
Environment="LOG_LEVEL=info"
Environment="USER_STORE_PATH=/var/lib/nanoproxy/data.db"

[Install]
WantedBy=multi-user.target
```

## Admin Console and Persistent Proxy Users

NanoProxy starts an admin console on `ADDR_ADMIN`.

- Visit `/` or `/admin` on the admin address.
- On first run (when no admin exists in `USER_STORE_PATH`), create the admin account at `/admin/setup`.
- After setup, log in using that admin account.
- Add or delete proxy users from the UI.
- Those proxy users are saved to `USER_STORE_PATH` and loaded again on restart.

Example:

```shell
export ADDR=:1080
export ADDR_HTTP=:8080
export ADDR_ADMIN=:9090
export USER_STORE_PATH=/var/lib/nanoproxy/data.db
export ADMIN_COOKIE_SECURE=true
export ADMIN_ALLOWED_ORIGINS=https://admin.example.com
go run .
```

### Admin Console Notes

- Admin-managed users are stored separately and reloaded automatically.
- Both HTTP and SOCKS5 reuse the same in-memory authentication view, so behavior stays aligned across protocols.

### Admin Security Notes

- Admin state-changing actions use CSRF tokens.
- CSRF tokens are rotated after successful state-changing actions.
- Login attempts are rate-limited (`ADMIN_MAX_LOGIN_ATTEMPTS`, `ADMIN_LOGIN_WINDOW`, `ADMIN_LOCKOUT_DURATION`).
- If `ADMIN_ALLOWED_ORIGINS` is configured, requests without allowed `Origin`/`Referer` are rejected.

## Notes

- All environment variables are optional and use sensible defaults
- SOCKS5 and HTTP proxy share the same credential store (database)
- All users are managed through the BoltDB database specified by `USER_STORE_PATH`
- Admin panel is accessible at `http://localhost:9090` (or configured `ADDR_ADMIN`)
- Initial admin account is set up through the `/admin/setup` web interface on first run
- Proxy users can be created and managed through the admin panel
- For production, always use `LOG_LEVEL=warn` or `error` to reduce log noise
- Database file location should be on persistent storage in containers/orchestration

