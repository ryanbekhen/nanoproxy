package credential

import (
	"github.com/stretchr/testify/assert"
	"testing"
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
