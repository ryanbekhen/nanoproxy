package resolver

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_Resolver_Resolve(t *testing.T) {
	var r Resolver
	r = &DNSResolver{}
	// Use localhost to avoid relying on public DNS/internet
	ip, err := r.Resolve("localhost")
	assert.NoError(t, err)
	assert.NotNil(t, ip)
}

func Test_Resolver_Resolve_Error(t *testing.T) {
	var r Resolver
	r = &DNSResolver{}
	// Use obviously invalid hostname to ensure deterministic error without external lookup
	ip, err := r.Resolve("invalid.invalid")
	assert.Error(t, err)
	assert.Nil(t, ip)
}
