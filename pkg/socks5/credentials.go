package socks5

import (
	"golang.org/x/crypto/bcrypt"
)

type CredentialStore interface {
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
