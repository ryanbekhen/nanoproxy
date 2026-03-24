# NanoProxy SOCKS5 Protocol Skill

## Description

Expertise in implementing and debugging the SOCKS5 protocol (RFC 1928) including authentication mechanisms, request
parsing, and connection handling.

## When to use this skill

- Implementing SOCKS5 protocol handlers
- Debugging SOCKS5 connection issues
- Adding authentication to SOCKS5
- Testing SOCKS5 client/server interactions
- Optimizing SOCKS5 performance

## Expertise areas

- RFC 1928 SOCKS5 protocol specification
- Authentication mechanisms (no-auth, username/password, GSSAPI)
- Request parsing and validation
- Connection establishment and teardown
- Error handling and protocol compliance
- Performance optimization for concurrent connections
- Testing strategies for SOCKS5

## Key files

- `pkg/socks5/socks5.go` - Main SOCKS5 server implementation
- `pkg/socks5/auth.go` - Authentication handler
- `pkg/socks5/request.go` - SOCKS5 request parsing
- `pkg/socks5/constants.go` - Protocol constants
- `pkg/socks5/errors.go` - Error types
- `pkg/socks5/socks5_test.go` - SOCKS5 tests
- `pkg/socks5/auth_test.go` - Authentication tests
- `pkg/socks5/request_test.go` - Request parsing tests

## Common tasks

### Writing a SOCKS5 authentication handler

Reference `pkg/socks5/auth.go` for the authentication pattern. Support username/password authentication with proper
error responses.

### Debugging connection issues

Check `pkg/socks5/request.go` for request parsing. Verify SOCKS version, command type, and address format compliance.

### Adding error handling

Use error types from `pkg/socks5/errors.go`. Always return proper SOCKS5 error codes before closing connection.

### Testing SOCKS5

Use the patterns in `pkg/socks5/*_test.go` files. Test both valid and invalid handshakes, all auth methods, and various
request types.

## Example patterns

### Handling a SOCKS5 greeting

```go
// Read greeting from client
greeting := make([]byte, 2)
_, err := io.ReadFull(conn, greeting)
if err != nil {
    return err
}

// Validate SOCKS version
if greeting[0] != socks5Version {
    return fmt.Errorf("invalid SOCKS version: %d", greeting[0])
}

// Select authentication method
numMethods := greeting[1]
methods := make([]byte, numMethods)
_, err = io.ReadFull(conn, methods)
if err != nil {
    return err
}
```

### Parsing a SOCKS5 request

```go
request := make([]byte, 4)
_, err := io.ReadFull(conn, request)
if err != nil {
    return err
}

cmd := request[1]  // CONNECT, BIND, or UDP
atyp := request[3] // Address type

// Parse address based on type
var addr string
switch atyp {
case ipv4Type:
    // Parse IPv4 address and port
case ipv6Type:
    // Parse IPv6 address and port
case domainType:
    // Parse domain name and port
}
```

## Testing approach

- Test all SOCKS5 commands (CONNECT, BIND, UDP ASSOCIATE)
- Test all authentication methods (NO AUTH, USERNAME/PASSWORD)
- Test various address types (IPv4, IPv6, domain names)
- Test protocol edge cases and malformed requests
- Verify error responses are SOCKS5 compliant
- Check connection cleanup and resource management

## Performance considerations

- Use buffered I/O for protocol parsing
- Implement timeouts for each phase
- Monitor goroutine usage for concurrent connections
- Consider connection pooling for destination servers
- Profile authentication overhead

## Security considerations

- Validate all input before processing
- Use constant-time comparison for password validation
- Never log passwords or sensitive authentication data
- Implement rate limiting for failed authentication attempts
- Properly close connections on authentication failure

## References

- RFC 1928: SOCKS Protocol Version 5
- NanoProxy architecture documentation in `architecture.md`
- Existing test cases in `pkg/socks5/*_test.go`

## Related skills

- HTTP Proxy Implementation - For comparing proxy protocols
- Credential Management - For auth handling
- DNS Resolution - For hostname resolution
- Go Concurrency - For connection handling

