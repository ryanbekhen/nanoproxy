---
name: credential-management
description: Use when working on proxy authentication and credential storage in pkg/credential — bcrypt hashing, constant-time/secure verification, the BoltDB-backed store, multiple users, and thread-safe access.
---

# Credential Management

Expertise in implementing secure credential storage, authentication validation, and credential management for proxy
access control in NanoProxy.

## When to use this skill

- Implementing credential storage mechanisms
- Adding user authentication to the proxy
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

Persist username/password pairs in the credential store (BoltDB at `USER_STORE_PATH`).

### Validating credentials

Implement secure credential validation; passwords are hashed with bcrypt.

### Supporting multiple users

Store and manage multiple username/password pairs safely.

## Example patterns

### Creating a credential store

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

### With hashing (preferred — matches NanoProxy's bcrypt usage)

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
- Monitor credential lookup time
- Profile authentication overhead

## Security considerations

- Never log passwords
- Use bcrypt for storage and constant-time comparison for in-memory secrets
- Clear sensitive data from memory
- Implement rate limiting
- Lock account after failed attempts
- Validate credential format

## References

- OWASP Authentication Cheat Sheet
- Go crypto/subtle package
- bcrypt password hashing library

## Related skills

- `socks5-protocol` - Uses credentials
- `http-proxy` - Uses credentials
- `go-concurrency` - For thread-safe access