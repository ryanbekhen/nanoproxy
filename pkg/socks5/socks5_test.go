package socks5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
	"net"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	conf := &Config{
		Authentication: []Authenticator{&NoAuthAuthenticator{}},
		Logger:         nil,
		Resolver:       &DNSResolver{},
	}

	server := New(conf)

	assert.NotNil(t, server)
	assert.Equal(t, conf, server.config)
	assert.NotNil(t, server.authentication)
	assert.IsType(t, &NoAuthAuthenticator{}, server.authentication[NoAuth])
}

func TestListenAndServe(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)

	go func() {
		conn, err := l.Accept()
		assert.NoError(t, err)
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadAtLeast(conn, buf, 4); err != nil {
			assert.NoError(t, err)
		}

		assert.Equal(t, []byte("ping"), buf)
		conn.Write([]byte("pong"))
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	credentials := StaticCredentialStore{
		"foo": "bar",
	}
	auth := &UserPassAuthenticator{Credentials: credentials}
	conf := &Config{
		Authentication: []Authenticator{auth},
	}
	server := New(conf)
	assert.NotNil(t, server)

	go func() {
		err := server.ListenAndServe("tcp", "127.0.0.1:12365")
		assert.NoError(t, err)
	}()
	time.Sleep(10 * time.Millisecond)

	conn, err := net.Dial("tcp", "127.0.0.1:12365")
	assert.NoError(t, err)

	req := bytes.NewBuffer(nil)
	req.Write([]byte{5})
	req.Write([]byte{2, NoAuth.Uint8(), UserPassAuth.Uint8()})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	req.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	req.Write(port)

	req.Write([]byte("ping"))

	conn.Write(req.Bytes())

	expected := []byte{
		Version, UserPassAuth.Uint8(),
		1, AuthSuccess.Uint8(),
		5,
		0,
		0,
		1,
		127, 0, 0, 1,
		0, 0,
		'p', 'o', 'n', 'g',
	}
	out := make([]byte, len(expected))

	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadAtLeast(conn, out, len(out)); err != nil {
		assert.NoError(t, err)
	}

	// Ignore port
	out[12] = 0
	out[13] = 0

	assert.Equal(t, expected, out)
}

func TestListenAndServe_InvalidCredentials(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)

	lAddr := l.Addr().(*net.TCPAddr)

	credentials := StaticCredentialStore{
		"foo": "bar",
	}
	auth := &UserPassAuthenticator{Credentials: credentials}
	conf := &Config{
		Authentication: []Authenticator{auth},
	}
	server := New(conf)
	assert.NotNil(t, server)

	go func() {
		err := server.ListenAndServe("tcp", "127.0.0.1:12366")
		assert.NoError(t, err)
	}()
	time.Sleep(10 * time.Millisecond)

	conn, err := net.Dial("tcp", "127.0.0.1:12366")
	assert.NoError(t, err)

	req := bytes.NewBuffer(nil)
	req.Write([]byte{5})
	req.Write([]byte{2, NoAuth.Uint8(), UserPassAuth.Uint8()})
	req.Write([]byte{1, 3, 'b', 'a', 'd', 3, 'p', 'a', 's', 's'}) // invalid username and password
	req.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	req.Write(port)

	req.Write([]byte("ping"))

	conn.Write(req.Bytes())

	expected := []byte{
		Version, UserPassAuth.Uint8(),
		1, AuthFailure.Uint8(), // expect authentication failure
	}
	out := make([]byte, len(expected))

	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadAtLeast(conn, out, len(out)); err != nil {
		assert.NoError(t, err)
	}

	assert.Equal(t, expected, out)
}

func TestListenAndServe_InvalidAuthType(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	lAddr := l.Addr().(*net.TCPAddr)

	credentials := StaticCredentialStore{
		"foo": "bar",
	}

	auth := &UserPassAuthenticator{Credentials: credentials}
	conf := &Config{
		Authentication: []Authenticator{auth},
	}

	server := New(conf)
	assert.NotNil(t, server)

	go func() {
		err := server.ListenAndServe("tcp", "127.0.0.1:12367")
		assert.NoError(t, err)

	}()
	time.Sleep(10 * time.Millisecond)

	conn, err := net.Dial("tcp", "127.0.0.1:12367")
	assert.NoError(t, err)

	req := bytes.NewBuffer(nil)
	req.Write([]byte{5})

	// invalid auth type
	req.Write([]byte{2, NoAuth.Uint8(), 0})
	req.Write([]byte{1, 3, 'f', 'o', 'o', 3, 'b', 'a', 'r'})
	req.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	req.Write(port)

	req.Write([]byte("ping"))

	conn.Write(req.Bytes())

	expected := []byte{
		Version, NoAcceptable.Uint8(),
	}

	out := make([]byte, len(expected))

	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadAtLeast(conn, out, len(out)); err != nil {
		assert.NoError(t, err)
	}

	assert.Equal(t, expected, out)
}

func TestListenAndServe_InvalidVersion(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	lAddr := l.Addr().(*net.TCPAddr)
	server := New(&Config{})
	assert.NotNil(t, server)

	go func() {
		err := server.ListenAndServe("tcp", "127.0.0.1:12368")
		assert.NoError(t, err)
	}()
	time.Sleep(10 * time.Millisecond)

	conn, err := net.Dial("tcp", "127.0.0.1:12368")
	assert.NoError(t, err)

	req := bytes.NewBuffer(nil)
	req.Write([]byte{4, NoAuth.Uint8(), 0})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	req.Write(port)
	conn.Write(req.Bytes())

	expected := []byte{
		0, NoAuth.Uint8(), // change expected version to 5
	}

	out := make([]byte, len(expected))

	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadAtLeast(conn, out, len(out)); err != nil {
		assert.Error(t, err)
	}

	assert.Equal(t, expected, out)
}

func TestRequest_Unreachable(t *testing.T) {
	s := &Server{
		config: &Config{
			Dial: func(network, addr string) (net.Conn, error) {
				// timeout
				timeout := time.Duration(1) * time.Millisecond
				conn, err := net.DialTimeout(network, addr, timeout)
				if err != nil {
					// Handle error here. For example, return an error or print a log.
					return nil, fmt.Errorf("failed to dial: %w", err)
				}
				return conn, nil
			},
		},
	}

	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{
		Version,
		CommandConnect.Uint8(),
		0,
		AddressTypeIPv4.Uint8(),
		192, 119, 119, 119,
	})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(12345))
	buf.Write(port)

	resp := &MockConn{}
	req, err := NewRequest(buf)
	assert.NoError(t, err)

	req.realAddr = req.DestAddr
	err = s.handleConnect(resp, req)
	assert.Error(t, err)

	out := resp.buf.Bytes()
	expected := []byte{
		Version,
		StatusHostUnreachable.Uint8(),
		0,
		AddressTypeIPv4.Uint8(),
		0, 0, 0, 0,
		0, 0,
	}

	assert.Equal(t, expected, out)
}

func TestRequest_Refused(t *testing.T) {
	s := &Server{
		config: &Config{},
	}

	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{
		Version,
		CommandConnect.Uint8(),
		0,
		AddressTypeIPv4.Uint8(),
		127, 0, 0, 1,
	})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(12345))
	buf.Write(port)

	resp := &MockConn{}
	req, err := NewRequest(buf)
	assert.NoError(t, err)

	req.realAddr = req.DestAddr
	err = s.handleConnect(resp, req)
	assert.Error(t, err)

	out := resp.buf.Bytes()
	expected := []byte{
		Version,
		StatusConnectionRefused.Uint8(),
		0,
		AddressTypeIPv4.Uint8(),
		0, 0, 0, 0,
		0, 0,
	}

	assert.Equal(t, expected, out)
}

func TestRequest_NetworkUnreachable(t *testing.T) {
	s := &Server{
		config: &Config{
			Dial: func(network, addr string) (net.Conn, error) {
				return nil, errors.New("unreachable network")
			},
		},
	}

	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{
		Version,
		CommandConnect.Uint8(),
		0,
		AddressTypeIPv4.Uint8(),
		192, 168, 111, 222,
	})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(12345))
	buf.Write(port)

	resp := &MockConn{}
	req, err := NewRequest(buf)
	assert.NoError(t, err)

	req.realAddr = req.DestAddr
	err = s.handleConnect(resp, req)
	assert.Error(t, err)

	out := resp.buf.Bytes()
	expected := []byte{
		Version,
		StatusNetworkUnreachable.Uint8(),
		0,
		AddressTypeIPv4.Uint8(),
		0, 0, 0, 0,
		0, 0,
	}

	assert.Equal(t, expected, out)
}

func TestRequest_CommandNotSupported(t *testing.T) {
	s := &Server{
		config: &Config{},
	}

	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{
		Version,
		CommandBind.Uint8(),
		0,
		AddressTypeIPv4.Uint8(),
		127, 0, 0, 1,
	})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(12345))
	buf.Write(port)

	resp := &MockConn{}
	req, err := NewRequest(buf)
	err = s.handleRequest(req, resp)
	assert.Error(t, err)

	out := resp.buf.Bytes()
	expected := []byte{
		Version,
		StatusCommandNotSupported.Uint8(),
		0,
		AddressTypeIPv4.Uint8(),
		0, 0, 0, 0,
		0, 0,
	}

	assert.Equal(t, expected, out)
}
