# DNS Resolution Skill

## Description

Expertise in implementing DNS resolution interfaces and custom resolver patterns for hostname-to-IP address translation
in the NanoProxy project.

## When to use this skill

- Implementing custom DNS resolvers
- Adding DNS caching functionality
- Debugging hostname resolution issues
- Integrating with different DNS backends
- Optimizing DNS lookup performance

## Expertise areas

- DNS resolver interface design
- Custom DNS implementation
- DNS caching strategies
- Error handling for DNS failures
- Performance optimization
- Testing DNS resolution

## Key files

- `pkg/resolver/resolver.go` - DNS resolver interface
- `pkg/resolver/resolver_test.go` - Resolver tests

## Common tasks

### Creating a custom resolver

Implement the resolver interface with Resolve method that takes hostname and returns IP address.

### Adding caching

Implement caching layer to reduce DNS lookups, with TTL support.

### Error handling

Properly handle NXDOMAIN, timeout, and other DNS errors.

## Example patterns

### Implementing resolver interface

```go
type Resolver interface {
    Resolve(hostname string) (string, error)
}

type DNSResolver struct {
    cache map[string]cachedResult
    ttl   time.Duration
}

func (r *DNSResolver) Resolve(hostname string) (string, error) {
    // Check cache
    if cached, ok := r.cache[hostname]; ok {
        if time.Now().Before(cached.expiry) {
            return cached.ip, nil
        }
    }
    
    // Resolve using system DNS
    addrs, err := net.LookupHost(hostname)
    if err != nil {
        return "", err
    }
    
    // Cache result
    r.cache[hostname] = cachedResult{
        ip:     addrs[0],
        expiry: time.Now().Add(r.ttl),
    }
    
    return addrs[0], nil
}
```

### Custom resolver with retry

```go
func (r *DNSResolver) ResolveWithRetry(hostname string, retries int) (string, error) {
    var lastErr error
    
    for i := 0; i < retries; i++ {
        ip, err := r.Resolve(hostname)
        if err == nil {
            return ip, nil
        }
        
        lastErr = err
        time.Sleep(time.Duration(i+1) * 100 * time.Millisecond)
    }
    
    return "", lastErr
}
```

## Testing approach

- Test with valid hostnames
- Test with invalid hostnames (NXDOMAIN)
- Test with localhost
- Test with IP addresses
- Test cache hit/miss
- Test TTL expiration
- Test concurrent resolution
- Test timeout scenarios

## Performance considerations

- Implement caching to reduce lookups
- Set appropriate TTL values
- Consider connection pooling for DNS
- Batch DNS queries when possible
- Monitor DNS lookup latency
- Profile resolver performance

## Security considerations

- Validate hostnames
- Prevent DNS poisoning
- Implement timeout to prevent hanging
- Consider DNSSEC validation
- Log DNS failures appropriately
- Handle DNS-based attacks

## References

- RFC 1035: Domain Names - Implementation and Specification
- Go net package documentation
- NanoProxy resolver usage

## Related skills

- SOCKS5 Protocol Implementation - Uses DNS resolution
- HTTP Proxy Implementation - Uses DNS resolution
- Go Concurrency - For concurrent DNS lookups

