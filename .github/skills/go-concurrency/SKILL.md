# Go Concurrency Skill

## Description

Expertise in Go concurrency patterns including goroutines, channels, synchronization, and concurrent network request
handling.

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
- `pkg/tor/dial.go` - Concurrent TOR connections

## Common tasks

### Handling concurrent connections

Accept multiple client connections and handle each concurrently.

### Implementing connection pooling

Maintain pool of reusable connections to destinations.

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

func NewConnPool(addr string, size int) *ConnPool {
	return &ConnPool{
		pool: make(chan net.Conn, size),
		addr: addr,
		size: size,
	}
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

### Channel-based work coordination

```go
func processRequests(requests <-chan Request, results chan<- Response) {
	for req := range requests {
		result := process(req)
		results <- result
	}
}

func (s *Server) handleStream(conn net.Conn) {
	requests := make(chan Request, 10)
	results := make(chan Response, 10)
	
	// Worker goroutines
	for i := 0; i < 4; i++ {
		go processRequests(requests, results)
	}
	
	// Read requests and write results
	go readRequests(conn, requests)
	go writeResults(conn, results)
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
		
		// Handle with context
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
	
	// Create worker goroutine with context awareness
	done := make(chan struct{})
	defer close(done)
	
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()
	
	// Process with proper cleanup
	s.process(conn)
}
```

## Testing approach

- Test concurrent access patterns
- Use race detector: `go test -race`
- Test for goroutine leaks
- Test timeout behavior
- Test channel closing
- Test synchronization
- Stress test with high concurrency
- Profile goroutine usage

## Performance considerations

- Limit number of goroutines
- Use buffered channels appropriately
- Implement connection pooling
- Set timeouts for operations
- Profile with pprof
- Monitor goroutine count
- Avoid busy-wait patterns
- Use worker pools for scalability

## Security considerations

- Implement timeouts to prevent hanging
- Properly close connections
- Validate concurrent access
- Prevent resource exhaustion
- Use context for cancellation
- Implement rate limiting
- Monitor for goroutine leaks
- Handle panics in goroutines

## References

- Effective Go - Concurrency section
- Go Concurrency Patterns talk
- Context package documentation
- Goroutine and Channel best practices

## Related skills

- SOCKS5 Protocol - Concurrent SOCKS5 handling
- HTTP Proxy - Concurrent proxy requests
- TOR Integration - Concurrent TOR connections
- Go Testing - Testing concurrent code

