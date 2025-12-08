package tor_test

import (
	"bytes"
	"fmt"
	"net"
	"testing"

	"github.com/ryanbekhen/nanoproxy/pkg/tor"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

type MockConn struct {
	net.Conn
	responses []string
	writeBuf  []string
	index     int
}

func (mc *MockConn) Read(b []byte) (n int, err error) {
	if mc.index >= len(mc.responses) {
		return 0, fmt.Errorf("EOF")
	}
	copy(b, mc.responses[mc.index])
	mc.index++
	return len(mc.responses[mc.index-1]), nil
}

func (mc *MockConn) Write(b []byte) (n int, err error) {
	mc.writeBuf = append(mc.writeBuf, string(b))
	return len(b), nil
}

func (mc *MockConn) Close() error {
	return nil
}

type MockDialer struct {
	net.Conn
	shouldFail bool
}

func (md *MockDialer) Dial(network, address string) (net.Conn, error) {
	if md.shouldFail {
		return nil, fmt.Errorf("failed to connect to tor control port")
	}
	return &MockConn{responses: []string{"250 OK\r\n", "250 OK\r\n"}}, nil
}

func (md *MockDialer) DialControlPort(network, address string) (net.Conn, error) {
	if md.shouldFail {
		return nil, fmt.Errorf("failed to connect to tor control port")
	}
	return &MockConn{responses: []string{"250 OK\r\n", "250 OK\r\n"}}, nil
}

func TestRequestNewTorIdentity_Success(t *testing.T) {
	logger := zerolog.New(zerolog.ConsoleWriter{Out: &bytes.Buffer{}}).With().Logger()
	dialer := &MockDialer{shouldFail: false}
	torController := tor.NewTorController(dialer)

	err := torController.RequestNewTorIdentity(&logger)
	assert.Nil(t, err, "expected no error during successful RequestNewTorIdentity call")
}

func TestRequestNewTorIdentity_FailConnect(t *testing.T) {
	logger := zerolog.New(zerolog.ConsoleWriter{Out: &bytes.Buffer{}}).With().Logger()
	dialer := &MockDialer{shouldFail: true}
	torController := tor.NewTorController(dialer)

	err := torController.RequestNewTorIdentity(&logger)
	assert.NotNil(t, err, "expected error when connection fails")
	assert.Contains(t, err.Error(), "failed to connect to tor control port")
}
