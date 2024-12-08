package tor

import (
	"errors"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

type MockDialer struct{}

func (MockDialer) Dial(network, address string) (net.Conn, error) {
	if address == "fail" {
		return nil, errors.New("simulated failure")
	}
	return &net.TCPConn{}, nil
}

func TestDial_Success(t *testing.T) {
	dialer := MockDialer{}
	conn, err := dialer.Dial("tcp", "example.com:80")
	assert.Nil(t, err, "expected no error while dialing")
	assert.NotNil(t, conn, "expected a connection to be obtained")
}

func TestDial_Error(t *testing.T) {
	dialer := MockDialer{}
	conn, err := dialer.Dial("tcp", "fail")
	assert.NotNil(t, err, "expected an error when dialing")
	assert.Nil(t, conn, "expected no connection on error")
}
