# HTTP Proxy Implementation Skill

## Description

Expertise in implementing HTTP and HTTPS proxy functionality including request forwarding, CONNECT tunneling, header
manipulation, and response handling.

## When to use this skill

- Implementing HTTP proxy request forwarding
- Adding HTTPS CONNECT tunnel support
- Debugging proxy forwarding issues
- Optimizing header handling
- Testing HTTP proxy functionality

## Expertise areas

- HTTP request parsing and validation
- HTTPS CONNECT tunnel establishment
- Header manipulation and preservation
- Request/response forwarding
- Keep-alive connection management
- Chunked transfer encoding handling
- Proxy authentication
- Performance optimization

## Key files

- `pkg/httpproxy/httpproxy.go` - HTTP proxy implementation
- `pkg/httpproxy/httpproxy_test.go` - HTTP proxy tests

## Common tasks

### Implementing HTTP request forwarding

Parse incoming HTTP request, validate target host/port, establish connection to destination, forward request headers and
body, relay response back.

### Handling HTTPS CONNECT

Parse CONNECT method, establish tunnel to destination, relay encrypted data bidirectionally between client and server.

### Managing headers

Preserve important headers (Host, User-Agent, etc.), remove connection-specific headers, handle hop-by-hop headers
correctly.

## Example patterns

### Forward HTTP request

```go
// Parse incoming request
req, err := http.ReadRequest(reader)
if err != nil {
    return err
}

// Validate target
host := req.Header.Get("Host")
if host == "" {
    host = req.URL.Host
}

// Connect to destination
client := &http.Client{
    Timeout: 30 * time.Second,
}
resp, err := client.Do(req)
if err != nil {
    return err
}

// Forward response
resp.Write(writer)
```

### Handle CONNECT method

```go
// Extract target host:port
parts := strings.Split(host, ":")
if len(parts) != 2 {
    return fmt.Errorf("invalid CONNECT target")
}

// Connect to destination
destConn, err := net.Dial("tcp", host)
if err != nil {
    return err
}

// Send 200 response
fmt.Fprintf(writer, "HTTP/1.1 200 Connection Established\r\n\r\n")

// Relay data bidirectionally
go io.Copy(destConn, clientConn)
io.Copy(clientConn, destConn)
```

## Testing approach

- Test HTTP GET, POST, PUT, DELETE methods
- Test HTTPS CONNECT tunnel establishment
- Test header preservation and filtering
- Test response code forwarding
- Test large request/response bodies
- Test chunked transfer encoding
- Test proxy authentication
- Test timeout and error handling

## Performance considerations

- Use io.Copy for efficient data transfer
- Implement appropriate timeouts
- Handle keep-alive connections
- Minimize memory allocations
- Consider connection pooling
- Monitor goroutine usage

## Security considerations

- Validate target host/port
- Check for SSRF vulnerabilities
- Implement proxy authentication
- Use TLS for sensitive data
- Validate HTTP headers
- Prevent header injection
- Rate limiting for connections
- Log proxy activity appropriately

## References

- RFC 7230: HTTP/1.1 Message Syntax and Routing
- RFC 7231: HTTP/1.1 Semantics and Content
- RFC 7232: HTTP/1.1 Conditional Requests
- HTTP CONNECT tunneling documentation

## Related skills

- SOCKS5 Protocol Implementation - Alternative proxy protocol
- Credential Management - For proxy authentication
- Go Concurrency - For connection handling

