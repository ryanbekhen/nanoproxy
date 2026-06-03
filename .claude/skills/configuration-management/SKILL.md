---
name: configuration-management
description: Use when adding or changing NanoProxy configuration — the env-driven struct config in pkg/config (caarlos0/env/v10), struct-tag defaults, and validation. Note real env vars (ADDR, ADDR_HTTP, TOR_ENABLED, USER_STORE_PATH).
---

# Configuration Management

Expertise in managing environment-based configuration for NanoProxy using struct-based parsing and environment
variables.

## When to use this skill

- Setting up NanoProxy configuration
- Adding new configuration options
- Handling environment variables
- Implementing configuration validation
- Managing configuration defaults

## Expertise areas

- Struct-based configuration parsing
- Environment variable handling
- Default values and validation
- Type conversion for config values
- Runtime configuration usage

## Key files

- `pkg/config/config.go` - Configuration implementation (uses `caarlos0/env/v10`)
- `nanoproxy.go` - Main entry point with config usage

## Notes specific to NanoProxy

- Config is env-driven only (no JSON/YAML files). The SOCKS5 listen address is `ADDR` (default `:1080`) and the HTTP
  proxy listen address is `ADDR_HTTP` (default `:8080`). Credentials are stored at `USER_STORE_PATH` (BoltDB).
- Always confirm the actual env tags in `pkg/config/config.go` before documenting or referencing them.

## Common tasks

### Defining configuration structure

Use struct tags to define configuration from environment variables.

### Parsing environment variables

Use the `caarlos0/env` library to automatically parse the struct from the environment.

### Setting defaults

Define default values in struct tags via `envDefault`.

### Validating configuration

Validate configuration values after parsing.

## Example patterns

### Configuration struct

```go
type Config struct {
    Addr           string `env:"ADDR" envDefault:":1080"`
    AddrHTTP       string `env:"ADDR_HTTP" envDefault:":8080"`
    TOREnabled     bool   `env:"TOR_ENABLED" envDefault:"false"`
    UserStorePath  string `env:"USER_STORE_PATH"`
    LogLevel       string `env:"LOG_LEVEL" envDefault:"info"`
}
```

### Parsing configuration

```go
cfg := &Config{}
if err := env.Parse(cfg); err != nil {
    logger.Fatal().Err(err).Msg("failed to parse config")
}

// Validate
if cfg.Addr == "" && cfg.AddrHTTP == "" {
    logger.Fatal().Msg("at least one proxy address must be configured")
}
```

## Testing approach

- Test with various environment variable combinations
- Test default value usage
- Test type conversion
- Test validation logic
- Test missing required values
- Test invalid value formats
- Test environment variable overrides

## Performance considerations

- Parse config once at startup
- Cache config values
- Avoid frequent environment variable reads

## Security considerations

- Never log sensitive values (passwords, secrets)
- Validate all config values
- Use environment variables for secrets
- Document required vs optional values

## References

- caarlos0/env GitHub repository
- Go struct tags documentation

## Related skills

- `credential-management` - Handling persisted proxy users and admin-auth flows
- `socks5-protocol` - Using config in SOCKS5 setup
- `http-proxy` - Using config in HTTP proxy setup