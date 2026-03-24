# Go Testing Skill

## Description

Expertise in writing Go unit tests, table-driven tests, mocks, and achieving high code coverage using the Testify
framework.

## When to use this skill

- Writing unit tests for Go code
- Creating table-driven tests
- Implementing mock objects
- Measuring test coverage
- Testing concurrent code
- Testing error conditions

## Expertise areas

- Go testing fundamentals
- Table-driven test patterns
- Testify assertion library
- Mock objects and test doubles
- Benchmarking and profiling
- Coverage analysis
- Testing concurrent code
- Integration testing

## Key files

- `pkg/socks5/*_test.go` - SOCKS5 tests
- `pkg/httpproxy/*_test.go` - HTTP proxy tests
- `pkg/resolver/*_test.go` - Resolver tests
- `pkg/credential/*_test.go` - Credential tests
- `pkg/tor/*_test.go` - TOR tests
- `cover.out` - Coverage file

## Common tasks

### Writing basic test

Use testing.T and write test function.

### Table-driven tests

Test multiple scenarios with single test function.

### Mock objects

Use testify/mock for complex dependencies.

### Coverage analysis

Run tests with coverage and generate HTML reports.

## Example patterns

### Basic test

```go
func TestResolve(t *testing.T) {
	resolver := &DNSResolver{}
	
	ip, err := resolver.Resolve("localhost")
	
	assert.NoError(t, err)
	assert.NotEmpty(t, ip)
}
```

### Table-driven test

```go
func TestParseRequest(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    *Request
		wantErr bool
	}{
		{
			name:    "valid CONNECT request",
			input:   []byte{5, 1, 0, 1, 127, 0, 0, 1, 0, 80},
			want:    &Request{Cmd: Connect, Addr: "127.0.0.1:80"},
			wantErr: false,
		},
		{
			name:    "invalid version",
			input:   []byte{4, 1, 0, 1, 127, 0, 0, 1, 0, 80},
			want:    nil,
			wantErr: true,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRequest(tt.input)
			
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
```

### Mock objects

```go
func TestProxyWithMockResolver(t *testing.T) {
	// Create mock
	mockResolver := new(MockResolver)
	mockResolver.On("Resolve", "example.com").Return("93.184.216.34", nil)
	
	// Use mock
	proxy := &Proxy{Resolver: mockResolver}
	ip, err := proxy.Resolve("example.com")
	
	// Verify
	assert.NoError(t, err)
	assert.Equal(t, "93.184.216.34", ip)
	mockResolver.AssertCalled(t, "Resolve", "example.com")
}
```

### Benchmarking

```go
func BenchmarkResolve(b *testing.B) {
	resolver := &DNSResolver{}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resolver.Resolve("example.com")
	}
}
```

## Testing approach

- Unit test each function
- Use table-driven tests for multiple cases
- Mock external dependencies
- Test error conditions
- Test edge cases
- Use assertions for clarity
- Measure coverage
- Write benchmarks for performance-critical code

## Performance considerations

- Use parallel tests when possible
- Cache test fixtures
- Avoid expensive operations in tests
- Profile test performance
- Use benchmarks to track regressions

## Security considerations

- Test authentication logic
- Test input validation
- Test error handling
- Don't include secrets in tests
- Test security edge cases

## References

- Go testing package documentation
- Testify GitHub repository
- Table-driven tests blog post
- Go benchmarking guide

## Related skills

- SOCKS5 Protocol - Testing SOCKS5 code
- HTTP Proxy - Testing proxy code
- Credential Management - Testing auth
- Go Concurrency - Testing concurrent code

