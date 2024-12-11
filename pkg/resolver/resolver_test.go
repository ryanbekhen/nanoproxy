package resolver

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_Resolver_Resolve(t *testing.T) {
	var r Resolver
	r = &DNSResolver{}
	ip, err := r.Resolve("www.google.com")
	assert.NoError(t, err)
	assert.NotNil(t, ip)
}

func Test_Resolver_Resolve_Error(t *testing.T) {
	var r Resolver
	r = &DNSResolver{}
	ip, err := r.Resolve("10.0.0.1.2")
	assert.Error(t, err)
	assert.Nil(t, ip)
}
