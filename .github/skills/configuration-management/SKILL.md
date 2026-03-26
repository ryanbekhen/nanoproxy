# Configuration Management Skill

## Description

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
- Configuration file parsing
- Runtime configuration updates

## Key files

- `pkg/config/config.go` - Configuration implementation
- `nanoproxy.go` - Main entry point with config usage

## Common tasks

### Defining configuration structure

Use struct tags to define configuration from environment variables.

### Parsing environment variables

Use `caarlos0/env` library to automatically parse struct from environment.

### Setting defaults

Define default values in struct tags.

### Validating configuration

Validate configuration values after parsing.

## Example patterns

### Configuration struct

```go
type Config struct {
SOCKS5Addr      string   `env:"SOCKS5_ADDR" envDefault:"0.0.0.0:1080"`
HTTPProxyAddr   string   `env:"HTTP_PROXY_ADDR" envDefault:"0.0.0.0:8080"`
TOREnabled      bool     `env:"TOR_ENABLED" envDefault:"false"`
TORControlAddr  string   `env:"TOR_CONTROLLER_ADDR" envDefault:"127.0.0.1:9051"`
Timezone        string   `env:"TIMEZONE" envDefault:"UTC"`
LogLevel        string   `env:"LOG_LEVEL" envDefault:"info"`
MaxConnections  int      `env:"MAX_CONNECTIONS" envDefault:"1000"`
RequestTimeout  int      `env:"REQUEST_TIMEOUT" envDefault:"30"`
}
```

### Parsing configuration

```go
cfg := &Config{}
if err := env.Parse(cfg); err != nil {
logger.Fatal().Err(err).Msg("failed to parse config")
}

// Validate
if cfg.SOCKS5Addr == "" && cfg.HTTPProxyAddr == "" {
logger.Fatal().Msg("at least one proxy address must be configured")
}

if cfg.MaxConnections < 1 {
logger.Fatal().Msg("MAX_CONNECTIONS must be >= 1")
}
```

### Using configuration

```go
func main() {
cfg := &Config{}
if err := env.Parse(cfg); err != nil {
logger.Fatal().Msg(err.Error())
}

// Use config values
socks5Server := &socks5.Server{
Addr: cfg.SOCKS5Addr,
Timeout: time.Duration(cfg.RequestTimeout) * time.Second,
}

if err := socks5Server.Listen(); err != nil {
logger.Fatal().Err(err).Msg("failed to start SOCKS5 server")
}
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
- Consider using config files for complex setups

## Security considerations

- Never log sensitive values (passwords, secrets)
- Validate all config values
- Use environment variables for secrets
- Consider using config encryption
- Document required vs optional values
- Implement config audit logging

## References

- caarlos0/env GitHub repository
- Environment variable best practices
- Go struct tags documentation

## Related skills

- Credential Management - Handling persisted proxy users and admin-auth flows
- Docker Deployment - Passing config via environment
- SOCKS5 Protocol - Using config in SOCKS5 setup
- HTTP Proxy - Using config in HTTP proxy setup

