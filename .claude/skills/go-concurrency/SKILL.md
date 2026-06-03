---
name: go-concurrency
description: Use when handling concurrent client connections, goroutine lifecycle, channels, context cancellation/timeouts, connection pooling, or preventing goroutine leaks in NanoProxy's proxy frontends.
---

# Go Concurrency

Expertise in Go concurrency patterns: goroutines, channels, synchronization, and concurrent network request handling.

## When to use this skill

- Handling concurrent client connections
- Implementing connection pooling
- Managing concurrent requests
- Using channels for communication
- Implementing proper synchronization
- Preventing goroutine leaks
- Optimizing concurrent performance

## Expertise areas

- Goroutine creation and management
- Channel communication patterns
- Synchronization primitives (mutex, rwmutex, sync)
- Context for cancellation and timeout
- Connection pooling
- Goroutine leak prevention
- Performance optimization
- Deadlock prevention

## Key files

- `nanoproxy.go` - Main goroutine management
- `pkg/socks5/socks5.go` - Concurrent connection handling
- `pkg/httpproxy/httpproxy.go` - Concurrent request handling
- `pkg/tor/dial.go` - Concurrent Tor connections

## Common tasks

### Handling concurrent connections

Accept multiple client connections and handle each concurrently.

### Implementing connection pooling

Maintain a pool of reusable connections to destinations.

### Using channels for communication

Coordinate work between goroutines using channels.

### Proper cleanup

Ensure goroutines are cleaned up and resources released.

## Example patterns

### Accepting concurrent connections

```go
func (s *Server) Serve(listener net.Listener) error {
    defer listener.Close()

    for {
        conn, err := listener.Accept()
        if err != nil {
            return err
        }

        // Handle each connection concurrently
        go s.handleConnection(conn)
    }
}

func (s *Server) handleConnection(conn net.Conn) {
    defer conn.Close()

    // Handle connection logic
    s.process(conn)
}
```

### Connection pooling

```go
type ConnPool struct {
    pool chan net.Conn
    addr string
    size int
}

func (p *ConnPool) Get(ctx context.Context) (net.Conn, error) {
    select {
    case conn := <-p.pool:
        return conn, nil
    case <-ctx.Done():
        return nil, ctx.Err()
    default:
        // Create new connection
        return net.DialContext(ctx, "tcp", p.addr)
    }
}

func (p *ConnPool) Put(conn net.Conn) {
    select {
    case p.pool <- conn:
    default:
        conn.Close()
    }
}
```

### Context for cancellation

```go
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
    defer listener.Close()

    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        default:
        }

        conn, err := listener.Accept()
        if err != nil {
            return err
        }

        go s.handleConnection(ctx, conn)
    }
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
    defer conn.Close()

    // Create timeout context
    ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()

    s.process(ctx, conn)
}
```

### Preventing goroutine leaks

```go
func (s *Server) handleConnection(ctx context.Context, conn net.Conn) {
    defer conn.Close()

    done := make(chan struct{})
    defer close(done)

    go func() {
        select {
        case <-ctx.Done():
            conn.Close()
        case <-done:
        }
    }()

    s.process(conn)
}
```

## Testing approach

- Test concurrent access patterns
- Use the race detector: `go test -race ./...`
- Test for goroutine leaks
- Test timeout behavior
- Test channel closing
- Stress test with high concurrency
- Profile goroutine usage

## Performance considerations

- Limit number of goroutines
- Use buffered channels appropriately
- Implement connection pooling
- Set timeouts for operations
- Profile with pprof
- Avoid busy-wait patterns
- Use worker pools for scalability

## Security considerations

- Implement timeouts to prevent hanging
- Properly close connections
- Prevent resource exhaustion
- Use context for cancellation
- Implement rate limiting
- Handle panics in goroutines

## References

- Effective Go - Concurrency section
- Go Concurrency Patterns talk
- Context package documentation

## Related skills

- `socks5-protocol` - Concurrent SOCKS5 handling
- `http-proxy` - Concurrent proxy requests
- `tor-integration` - Concurrent Tor connections
- `go-testing` - Testing concurrent code