package tor

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
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
	customSOCKS5 = mockSOCKS5                        // Replace with mock
	defer func() { customSOCKS5 = originalSOCKS5 }() // Restore after test

	serverMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "OK")
	}))
	defer serverMock.Close()

	dialer := DefaultDialer{}
	conn, err := dialer.DialControlPort("tcp", serverMock.Listener.Addr().String())
	assert.Nil(t, err, "expected no error during successful dial")
	assert.NotNil(t, conn, "expected a valid connection on successful dial")
}
