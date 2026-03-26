package credential

import (
	"sort"
	"sync"

	"golang.org/x/crypto/bcrypt"
)

type Store interface {
	Add(user, password string)
	Valid(user, password string) bool
}

type CombinedStore struct {
	stores []Store
}

func NewCombinedStore(stores ...Store) *CombinedStore {
	filtered := make([]Store, 0, len(stores))
	for _, store := range stores {
		if store != nil {
			filtered = append(filtered, store)
		}
	}

	return &CombinedStore{stores: filtered}
}

func (s *CombinedStore) Add(user, password string) {
	if len(s.stores) == 0 {
		return
	}

	s.stores[0].Add(user, password)
}

func (s *CombinedStore) Valid(user, password string) bool {
	for _, store := range s.stores {
		if store.Valid(user, password) {
			return true
		}
	}

	return false
}

type StaticCredentialStore struct {
	store map[string]string
	mu    sync.RWMutex
}

func NewStaticCredentialStore() *StaticCredentialStore {
	return &StaticCredentialStore{
		store: make(map[string]string),
	}
}

func (s *StaticCredentialStore) Add(user, password string) {
	hash, err := normalizePassword(password)
	if err != nil {
		return
	}

	s.SetHashed(user, hash)
}

func (s *StaticCredentialStore) SetHashed(user, passwordHash string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[user] = passwordHash
}

func (s *StaticCredentialStore) Valid(user, password string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pass, ok := s.store[user]
	if !ok {
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(pass), []byte(password))
	return err == nil
}

func (s *StaticCredentialStore) Delete(user string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.store[user]; !ok {
		return false
	}

	delete(s.store, user)
	return true
}

func (s *StaticCredentialStore) ListUsers() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make([]string, 0, len(s.store))
	for user := range s.store {
		users = append(users, user)
	}

	sort.Strings(users)
	return users
}

func (s *StaticCredentialStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return len(s.store)
}

func (s *StaticCredentialStore) Exists(user string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, ok := s.store[user]
	return ok
}

func (s *StaticCredentialStore) GetHashed(user string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	pass, ok := s.store[user]
	return pass, ok
}

func (s *StaticCredentialStore) Snapshot() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clone := make(map[string]string, len(s.store))
	for user, pass := range s.store {
		clone[user] = pass
	}

	return clone
}

func (s *StaticCredentialStore) Replace(snapshot map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.store = make(map[string]string, len(snapshot))
	for user, pass := range snapshot {
		s.store[user] = pass
	}
}

func normalizePassword(password string) (string, error) {
	if _, err := bcrypt.Cost([]byte(password)); err == nil {
		// The credential is already a bcrypt hash, keep it as-is.
		return password, nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}
