# TOR Integration Skill

## Description

Expertise in integrating TOR network for anonymized proxy connections, including TOR controller communication, circuit
management, and identity rotation.

## When to use this skill

- Implementing TOR connection support
- Managing TOR circuits and identities
- Debugging TOR connectivity issues
- Configuring TOR service integration
- Optimizing TOR performance

## Expertise areas

- TOR control port protocol
- Circuit management and rotation
- Identity and exit node selection
- TOR daemon integration
- Error handling for TOR failures
- Performance optimization
- Testing TOR integration

## Key files

- `pkg/tor/controller.go` - TOR control port communication
- `pkg/tor/dial.go` - TOR connection establishment
- `pkg/tor/identity.go` - Identity management
- `pkg/tor/requester.go` - Request handling through TOR
- `pkg/tor/controller_test.go` - Controller tests
- `pkg/tor/dial_test.go` - Dial tests
- `pkg/tor/identity_test.go` - Identity tests
- `Dockerfile-tor` - TOR service Docker configuration
- `supervisord.conf` - TOR service management

## Common tasks

### Connecting through TOR

Establish connection to TOR SOCKS5 port and use it like regular SOCKS5 proxy.

### Managing circuits

Request new circuits from TOR controller for identity rotation and privacy.

### Handling TOR failures

Gracefully handle TOR service unavailability and reconnection.

### Configuring TOR service

Set up TOR daemon with proper configuration for NanoProxy.

## Example patterns

### TOR controller communication

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

### Creating new circuit

```go
func (c *Controller) NewCircuit() error {
    return c.Signal("NEWNYM")
}

func (c *Controller) SetIdentity(nickname string) error {
    cmd := fmt.Sprintf("SETCONF __LeaveStreamsUnattached=1\r\n")
    _, err := c.conn.Write([]byte(cmd))
    return err
}
```

### Dialing through TOR

```go
func (d *Dialer) Dial(network, addr string) (net.Conn, error) {
    // Connect to TOR SOCKS5 port
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

- Mock TOR controller responses
- Test circuit creation
- Test identity rotation
- Test connection establishment
- Test error handling
- Test timeout behavior
- Test with actual TOR daemon
- Test concurrent requests

## Performance considerations

- Cache controller connection
- Batch circuit requests
- Implement circuit pooling
- Monitor TOR latency
- Set appropriate timeouts
- Profile TOR overhead
- Consider pre-warming circuits

## Security considerations

- Validate TOR controller authentication
- Don't leak circuit identities in logs
- Implement identity rotation
- Handle TOR service failures gracefully
- Verify TOR daemon is running
- Secure TOR controller port access
- Implement timeout to prevent hanging
- Consider using Tor Browser for testing

## References

- TOR Control Port Protocol Specification
- TOR Project Documentation
- TOR SOCKS5 Interface
- NanoProxy TOR integration guide

## Related skills

- SOCKS5 Protocol Implementation - TOR uses SOCKS5
- Credential Management - TOR controller auth
- Configuration Management - TOR configuration
- Docker Deployment - TOR service container
- Go Concurrency - Concurrent TOR requests

