package credential

import (
	"golang.org/x/crypto/bcrypt"
)

type Store interface {
	Add(user, password string)
	Valid(user, password string) bool
}

type StaticCredentialStore struct {
	store map[string]string
}

func NewStaticCredentialStore() *StaticCredentialStore {
	return &StaticCredentialStore{
		store: make(map[string]string),
	}
}

func (s StaticCredentialStore) Add(user, password string) {
	s.store[user] = password
}

func (s StaticCredentialStore) Valid(user, password string) bool {
	pass, ok := s.store[user]
	if !ok {
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(pass), []byte(password))
	return err == nil
}
