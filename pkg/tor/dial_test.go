package tor

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/proxy"
	"testing"
)

func TestDial(t *testing.T) {
	network := "tcp"
	addr := "example.com:80"

	conn, err := DefaultDialer{}.Dial(network, addr)
	assert.Nil(t, err)
	defer conn.Close()
	assert.NotNil(t, conn)
}

func TestDial_Error(t *testing.T) {
	originalSOCKS5 := customSOCKS5
	customSOCKS5 = func(network, address string, auth *proxy.Auth, forward proxy.Dialer) (proxy.Dialer, error) {
		return nil, fmt.Errorf("simulated SOCKS5 error")
	}
	defer func() { customSOCKS5 = originalSOCKS5 }()

	network := "tcp"
	addr := "example.com:80"
	conn, err := DefaultDialer{}.Dial(network, addr)

	assert.NotNil(t, err, "expected an error when dialing with simulated SOCKS5 error")
	assert.Nil(t, conn, "expected no connection to be returned on error")
}
