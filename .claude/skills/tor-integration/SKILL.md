---
name: tor-integration
description: Use when working on Tor support in pkg/tor — control-port (NEWNYM) signaling, circuit and identity rotation, dialing through the Tor SOCKS port, or the Dockerfile-tor/supervisord deployment.
---

# Tor Integration

Expertise in integrating the Tor network for anonymized proxy connections: Tor controller communication, circuit
management, and identity rotation.

## When to use this skill

- Implementing Tor connection support
- Managing Tor circuits and identities
- Debugging Tor connectivity issues
- Configuring Tor service integration
- Optimizing Tor performance

## Expertise areas

- Tor control port protocol
- Circuit management and rotation
- Identity and exit node selection
- Tor daemon integration
- Error handling for Tor failures
- Performance optimization
- Testing Tor integration

## Key files

- `pkg/tor/controller.go` - Tor control port communication
- `pkg/tor/dial.go` - Tor connection establishment
- `pkg/tor/identity.go` - Identity management
- `pkg/tor/requester.go` - Request handling through Tor
- `pkg/tor/controller_test.go` - Controller tests
- `pkg/tor/dial_test.go` - Dial tests
- `pkg/tor/identity_test.go` - Identity tests
- `Dockerfile-tor` - Tor service Docker configuration
- `supervisord.conf` - Tor service management

## Common tasks

### Connecting through Tor

Establish connection to Tor SOCKS5 port and use it like a regular SOCKS5 proxy.

### Managing circuits

Request new circuits from Tor controller for identity rotation and privacy.

### Handling Tor failures

Gracefully handle Tor service unavailability and reconnection.

### Configuring Tor service

Set up the Tor daemon with proper configuration for NanoProxy.

## Example patterns

### Tor controller communication

```go
type Controller struct {
    addr string // e.g., "127.0.0.1:9051"
    conn net.Conn
}

func (c *Controller) Signal(signal string) error {
    cmd := fmt.Sprintf("SIGNAL %s\r\n", signal)
    _, err := c.conn.Write([]byte(cmd))
    if err != nil {
        return err
    }

    // Read response
    response := make([]byte, 1024)
    n, err := c.conn.Read(response)
    if err != nil {
        return err
    }

    // Parse response (should start with 250)
    if !strings.HasPrefix(string(response[:n]), "250") {
        return fmt.Errorf("controller error: %s", string(response[:n]))
    }

    return nil
}
```

### Creating a new circuit

```go
func (c *Controller) NewCircuit() error {
    return c.Signal("NEWNYM")
}
```

### Dialing through Tor

```go
func (d *Dialer) Dial(network, addr string) (net.Conn, error) {
    // Connect to Tor SOCKS5 port
    conn, err := net.Dial("tcp", d.torSocks5Addr)
    if err != nil {
        return nil, err
    }

    // Perform SOCKS5 handshake
    // ... SOCKS5 protocol ...

    return conn, nil
}
```

## Testing approach

- Mock Tor controller responses
- Test circuit creation
- Test identity rotation
- Test connection establishment
- Test error handling
- Test timeout behavior
- Test with actual Tor daemon
- Test concurrent requests

## Performance considerations

- Cache controller connection
- Batch circuit requests
- Implement circuit pooling
- Monitor Tor latency
- Set appropriate timeouts
- Profile Tor overhead
- Consider pre-warming circuits

## Security considerations

- Validate Tor controller authentication
- Don't leak circuit identities in logs
- Implement identity rotation
- Handle Tor service failures gracefully
- Verify the Tor daemon is running
- Secure Tor controller port access
- Implement timeout to prevent hanging

## References

- Tor Control Port Protocol Specification
- Tor Project Documentation
- Tor SOCKS5 Interface

## Related skills

- `socks5-protocol` - Tor uses SOCKS5
- `credential-management` - Tor controller auth
- `configuration-management` - Tor configuration
- `go-concurrency` - Concurrent Tor requests