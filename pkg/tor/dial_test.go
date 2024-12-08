package tor

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/proxy"
)

// Assume customSOCKS5 original function
var originalSOCKS5 = customSOCKS5

func mockSOCKS5(network, address string, auth *proxy.Auth, forward proxy.Dialer) (proxy.Dialer, error) {
	return &MockProxyDialer{}, nil
}

type MockProxyDialer struct{}

func (m *MockProxyDialer) Dial(network, address string) (net.Conn, error) {
	if address == "fail" {
		return nil, fmt.Errorf("simulated Dial failure")
	}
	return &net.TCPConn{}, nil
}

func TestDefaultDialer_Dial_Success(t *testing.T) {
	customSOCKS5 = mockSOCKS5                        // Replace with mock
	defer func() { customSOCKS5 = originalSOCKS5 }() // Restore after test

	dialer := DefaultDialer{}
	conn, err := dialer.Dial("tcp", "example.com:80")
	assert.Nil(t, err, "expected no error during successful dial")
	assert.NotNil(t, conn, "expected a valid connection on successful dial")
}

func TestDefaultDialer_Dial_Failure(t *testing.T) {
	customSOCKS5 = mockSOCKS5                        // Replace with mock
	defer func() { customSOCKS5 = originalSOCKS5 }() // Restore after test

	dialer := DefaultDialer{}
	conn, err := dialer.Dial("tcp", "fail")
	assert.NotNil(t, err, "expected an error during dial failure simulation")
	assert.Nil(t, conn, "expected no connection on dial failure")
}

func TestDefaultDialer_DialControlPort(t *testing.T) {
	tests := []struct {
		name    string
		address string
		wantErr bool
	}{
		{"successful connection", "localhost:9051", false},
		{"failed connection", "invalid:address", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dialer := DefaultDialer{}
			conn, err := dialer.DialControlPort("tcp", tt.address)

			if tt.wantErr {
				assert.NotNil(t, err, "expected an error for: %s", tt.name)
				assert.Nil(t, conn, "expected no connection for: %s", tt.name)
			} else {
				assert.Nil(t, err, "expected no error for: %s", tt.name)
				assert.NotNil(t, conn, "expected a valid connection for: %s", tt.name)
			}
		})
	}
}
