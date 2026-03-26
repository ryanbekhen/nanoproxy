package credential

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_CredentialStore_Valid(t *testing.T) {
	s := StaticCredentialStore{
		store: map[string]string{
			"foo": "$2y$05$Xr4Vj6wbsCuf70.Fif2guuX8Ez97GB0VysyCTRL2EMkIikCpY/ugi",
		},
	}
	assert.True(t, s.Valid("foo", "bar"))
	assert.False(t, s.Valid("foo", "baz"))
	assert.False(t, s.Valid("baz", "bar"))
}

func Test_CredentialStore_AddPlaintext_ThenValid(t *testing.T) {
	s := NewStaticCredentialStore()

	s.Add("foo", "bar")

	assert.True(t, s.Valid("foo", "bar"))
	assert.False(t, s.Valid("foo", "baz"))
}

func Test_CredentialStore_AddBcryptHash_ThenValid(t *testing.T) {
	s := NewStaticCredentialStore()

	s.Add("foo", "$2y$05$Xr4Vj6wbsCuf70.Fif2guuX8Ez97GB0VysyCTRL2EMkIikCpY/ugi")

	assert.True(t, s.Valid("foo", "bar"))
	assert.False(t, s.Valid("foo", "baz"))
}

func Test_CredentialStore_Delete(t *testing.T) {
	s := NewStaticCredentialStore()
	s.Add("foo", "bar")

	assert.True(t, s.Delete("foo"))
	assert.False(t, s.Valid("foo", "bar"))
	assert.False(t, s.Delete("foo"))
}

func Test_CredentialStore_ListUsers(t *testing.T) {
	s := NewStaticCredentialStore()
	s.Add("charlie", "secret")
	s.Add("alice", "secret")
	s.Add("bob", "secret")

	assert.Equal(t, []string{"alice", "bob", "charlie"}, s.ListUsers())
	assert.Equal(t, 3, s.Count())
	assert.True(t, s.Exists("alice"))
	assert.False(t, s.Exists("nobody"))
}
