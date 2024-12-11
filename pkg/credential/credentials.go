package credential

import (
	"golang.org/x/crypto/bcrypt"
)

type Store interface {
	Valid(user, password string) bool
}

type StaticCredentialStore map[string]string

func (s StaticCredentialStore) Valid(user, password string) bool {
	pass, ok := s[user]
	if !ok {
		return false
	}

	err := bcrypt.CompareHashAndPassword([]byte(pass), []byte(password))
	return err == nil
}
