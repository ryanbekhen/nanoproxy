package socks5

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_CredentialStore_Valid(t *testing.T) {
	var s CredentialStore
	s = StaticCredentialStore{
		"foo": "bar",
	}
	assert.True(t, s.Valid("foo", "bar"))
	assert.False(t, s.Valid("foo", "baz"))
	assert.False(t, s.Valid("baz", "bar"))
}
