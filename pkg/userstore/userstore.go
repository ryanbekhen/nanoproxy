package userstore

import (
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"os"
	"sync"
)

// User represents a user in the system
type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

// Store provides persistent user storage
type Store struct {
	users    map[string]*User
	filePath string
	mu       sync.RWMutex
}

// NewStore creates a new user store that persists to a file
func NewStore(filePath string) (*Store, error) {
	store := &Store{
		users:    make(map[string]*User),
		filePath: filePath,
	}

	if err := store.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}

	return store, nil
}

// Add adds or updates a user with a plaintext password (will be hashed)
// This version doesn't return an error to match credential.Store interface
func (s *Store) Add(username, password string) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		// Log error but don't return it for interface compatibility
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.users[username] = &User{
		Username:     username,
		PasswordHash: string(hash),
	}

	s.save() // Ignore error for interface compatibility
}

// AddUser adds or updates a user with a plaintext password (will be hashed)
// This version returns an error for use in the admin API
func (s *Store) AddUser(username, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.users[username] = &User{
		Username:     username,
		PasswordHash: string(hash),
	}

	return s.save()
}

// AddWithHash adds or updates a user with a pre-hashed password
func (s *Store) AddWithHash(username, passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.users[username] = &User{
		Username:     username,
		PasswordHash: passwordHash,
	}

	return s.save()
}

// Valid checks if a username and password combination is valid
func (s *Store) Valid(username, password string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.users[username]
	if !ok {
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	return err == nil
}

// Delete removes a user from the store
func (s *Store) Delete(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.users, username)
	return s.save()
}

// List returns all usernames
func (s *Store) List() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	usernames := make([]string, 0, len(s.users))
	for username := range s.users {
		usernames = append(usernames, username)
	}
	return usernames
}

// Get returns a user by username
func (s *Store) Get(username string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.users[username]
	return user, ok
}

// Count returns the number of users
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.users)
}

// load reads users from the file
func (s *Store) load() error {
	data, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}

	var users []*User
	if err := json.Unmarshal(data, &users); err != nil {
		return err
	}

	for _, user := range users {
		s.users[user.Username] = user
	}

	return nil
}

// save writes users to the file
func (s *Store) save() error {
	users := make([]*User, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, user)
	}

	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(s.filePath, data, 0600)
}
