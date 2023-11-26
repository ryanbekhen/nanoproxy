package socks5

type CredentialStore interface {
	Valid(user, password string) bool
}

type StaticCredentialStore map[string]string

func (s StaticCredentialStore) Valid(user, password string) bool {
	pass, ok := s[user]
	if !ok {
		return false
	}
	return password == pass
}
