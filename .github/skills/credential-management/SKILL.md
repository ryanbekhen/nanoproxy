# Credential Management Skill

## Description

Expertise in implementing secure credential storage, authentication validation, and credential management for proxy
access control in NanoProxy.

## When to use this skill

- Implementing credential storage mechanisms
- Adding user authentication to proxy
- Validating credentials securely
- Managing multiple user accounts
- Implementing rate limiting for auth failures

## Expertise areas

- Credential storage patterns
- Authentication validation
- Password hashing and comparison
- Memory security
- Concurrent credential access
- Testing authentication logic
- Security best practices

## Key files

- `pkg/credential/credentials.go` - Credential storage implementation
- `pkg/credential/credentials_test.go` - Credential tests

## Common tasks

### Storing credentials

Use StaticCredentialStore to store username/password pairs in memory.

### Validating credentials

Implement secure credential validation with constant-time comparison.

### Supporting multiple users

Store and manage multiple username/password pairs safely.

## Example patterns

### Creating credential store

```go
type CredentialStore interface {
    Add(username, password string)
    Verify(username, password string) bool
}

type StaticCredentialStore struct {
    credentials map[string]string
    mu          sync.RWMutex
}

func NewStaticCredentialStore() *StaticCredentialStore {
    return &StaticCredentialStore{
        credentials: make(map[string]string),
    }
}

func (s *StaticCredentialStore) Add(username, password string) {
    s.mu.Lock()
    defer s.mu.Unlock()
    s.credentials[username] = password
}

func (s *StaticCredentialStore) Verify(username, password string) bool {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    expectedPassword, ok := s.credentials[username]
    if !ok {
        return false
    }
    
    // Use constant-time comparison
    return subtle.ConstantTimeCompare(
        []byte(password),
        []byte(expectedPassword),
    ) == 1
}
```

### With hashing (more secure)

```go
func (s *StaticCredentialStore) Add(username, password string) {
    s.mu.Lock()
    defer s.mu.Unlock()
    
    hash, err := bcrypt.GenerateFromPassword(
        []byte(password),
        bcrypt.DefaultCost,
    )
    if err != nil {
        log.Error().Err(err).Msg("failed to hash password")
        return
    }
    
    s.credentials[username] = string(hash)
}

func (s *StaticCredentialStore) Verify(username, password string) bool {
    s.mu.RLock()
    defer s.mu.RUnlock()
    
    hash, ok := s.credentials[username]
    if !ok {
        return false
    }
    
    err := bcrypt.CompareHashAndPassword(
        []byte(hash),
        []byte(password),
    )
    return err == nil
}
```

## Testing approach

- Test adding credentials
- Test valid password verification
- Test invalid password rejection
- Test missing user handling
- Test concurrent access
- Test with special characters
- Test with empty credentials
- Test thread safety

## Performance considerations

- Use RWMutex for concurrent reads
- Cache verification results temporarily
- Implement connection pooling
- Monitor credential lookup time
- Profile authentication overhead

## Security considerations

- Never log passwords
- Use constant-time comparison
- Consider hashing passwords
- Clear sensitive data from memory
- Implement rate limiting
- Lock account after failed attempts
- Use secure random for tokens
- Validate credential format

## References

- OWASP Authentication Cheat Sheet
- Go crypto/subtle package
- bcrypt password hashing library

## Related skills

- SOCKS5 Protocol Implementation - Uses credentials
- HTTP Proxy Implementation - Uses credentials
- Go Concurrency - For thread-safe access

