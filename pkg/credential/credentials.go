package credential

import (
	"golang.org/x/crypto/bcrypt"
)

type Store interface {
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
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return
	}

	s.store[user] = string(hash)
}

func (s StaticCredentialStore) Valid(user, password string) bool {
	pass, ok := s.store[user]
	if !ok {
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(pass), []byte(password))
	return err == nil
}
