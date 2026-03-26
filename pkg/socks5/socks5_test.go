package socks5

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/ryanbekhen/nanoproxy/pkg/credential"
	"github.com/ryanbekhen/nanoproxy/pkg/resolver"
	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	conf := &Config{
		Authentication: []Authenticator{&NoAuthAuthenticator{}},
		Logger:         nil,
		Resolver:       &resolver.DNSResolver{},
	}

	server := New(conf)

	assert.NotNil(t, server)
	assert.Equal(t, conf, server.config)
	assert.NotNil(t, server.authentication)
	assert.IsType(t, &NoAuthAuthenticator{}, server.authentication[NoAuth])
}

func TestNew_WithCredentials(t *testing.T) {
	creds := credential.NewStaticCredentialStore()
	creds.Add("user", "pass")
	conf := &Config{Credentials: creds}
	server := New(conf)
	assert.NotNil(t, server)
	_, ok := server.authentication[UserPassAuth]
	assert.True(t, ok)
}

func TestNew_DefaultNoAuth(t *testing.T) {
	conf := &Config{} // no Authentication, no Credentials → NoAuthAuthenticator
	server := New(conf)
	assert.NotNil(t, server)
	_, ok := server.authentication[NoAuth]
	assert.True(t, ok)
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

	credentials := credential.NewStaticCredentialStore()
	credentials.Add("foo", "$2y$05$Xr4Vj6wbsCuf70.Fif2guuX8Ez97GB0VysyCTRL2EMkIikCpY/ugi")

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

	credentials := credential.NewStaticCredentialStore()
	credentials.Add("foo", "bar")
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

func TestHandleConnection_LogsStructuredAuthFailure(t *testing.T) {
	var logBuf bytes.Buffer
	logger := zerolog.New(&logBuf)
	credentials := credential.NewStaticCredentialStore()
	credentials.Add("foo", "bar")

	server := New(&Config{
		Authentication: []Authenticator{&UserPassAuthenticator{Credentials: credentials}},
		Logger:         &logger,
	})

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		server.handleConnection(serverConn)
	}()

	request := []byte{
		Version,
		1, UserPassAuth.Uint8(),
		UserAuthVersion,
		3, 'b', 'a', 'd',
		4, 'p', 'a', 's', 's',
	}
	_, err := clientConn.Write(request)
	assert.NoError(t, err)

	response := make([]byte, 4)
	_, err = io.ReadFull(clientConn, response)
	assert.NoError(t, err)
	assert.Equal(t, []byte{Version, UserPassAuth.Uint8(), UserAuthVersion, AuthFailure.Uint8()}, response)

	clientConn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for connection handler")
	}

	entry := map[string]interface{}{}
	err = json.Unmarshal(bytes.TrimSpace(logBuf.Bytes()), &entry)
	assert.NoError(t, err)
	assert.Equal(t, "proxy authentication failed", entry["message"])
	assert.Equal(t, "socks5", entry["protocol"])
	assert.Equal(t, "invalid credentials", entry["error"])
	assert.Equal(t, "error", entry["level"])
	assert.NotEmpty(t, entry["client_addr"])
}

func TestHandleConnection_LogsClientAddrForUnsupportedVersion(t *testing.T) {
	var logBuf bytes.Buffer
	logger := zerolog.New(&logBuf)
	server := New(&Config{Logger: &logger})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer listener.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, acceptErr := listener.Accept()
		assert.NoError(t, acceptErr)
		if acceptErr == nil {
			server.handleConnection(conn)
		}
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	assert.NoError(t, err)
	_, err = clientConn.Write([]byte{0x04})
	assert.NoError(t, err)
	_ = clientConn.Close()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for connection handler")
	}

	entry := map[string]interface{}{}
	err = json.Unmarshal(bytes.TrimSpace(logBuf.Bytes()), &entry)
	assert.NoError(t, err)
	assert.Equal(t, "unsupported version", entry["message"])
	assert.Equal(t, "socks5", entry["protocol"])
	assert.Equal(t, float64(4), entry["version"])
	clientAddr, ok := entry["client_addr"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, clientAddr)
	assert.Contains(t, clientAddr, "127.0.0.1:")
}

func TestHandleConnection_LogsRequestFailureContext(t *testing.T) {
	var logBuf bytes.Buffer
	logger := zerolog.New(&logBuf)
	server := New(&Config{
		Authentication: []Authenticator{&NoAuthAuthenticator{}},
		Logger:         &logger,
	})

	serverConn, clientConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		server.handleConnection(serverConn)
	}()

	request := []byte{
		Version,
		1, NoAuth.Uint8(),
		Version,
		9, // unsupported command
		0,
		AddressTypeIPv4.Uint8(),
		127, 0, 0, 1,
		0, 80,
	}
	_, err := clientConn.Write(request)
	assert.NoError(t, err)

	response := make([]byte, 12)
	_, err = io.ReadFull(clientConn, response)
	assert.NoError(t, err)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for connection handler")
	}

	entry := map[string]interface{}{}
	err = json.Unmarshal(bytes.TrimSpace(logBuf.Bytes()), &entry)
	assert.NoError(t, err)
	assert.Equal(t, "request failed", entry["message"])
	assert.Equal(t, "socks5", entry["protocol"])
	assert.Equal(t, "unknown", entry["command"])
	assert.Equal(t, "127.0.0.1:80", entry["dest_addr"])
	assert.Equal(t, "unsupported command: 9", entry["error"])
	assert.Equal(t, "error", entry["level"])
	clientAddr, ok := entry["client_addr"].(string)
	assert.True(t, ok)
	assert.NotEmpty(t, clientAddr)
}

func TestListenAndServe_InvalidAuthType(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	lAddr := l.Addr().(*net.TCPAddr)

	credentials := credential.NewStaticCredentialStore()
	credentials.Add("foo", "bar")

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
	err = s.handleConnect(resp, req, nil)
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
	err = s.handleConnect(resp, req, nil)
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
	err = s.handleConnect(resp, req, nil)
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
	req, _ := NewRequest(buf)
	err := s.handleRequest(req, resp, nil)
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

func TestShutdown_NilListener(t *testing.T) {
	server := New(&Config{})
	err := server.Shutdown()
	assert.NoError(t, err)
}

func TestShutdown_WithListener(t *testing.T) {
	server := New(&Config{})
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe("tcp", "127.0.0.1:0")
	}()
	// Give the goroutine time to start listening
	time.Sleep(20 * time.Millisecond)
	err := server.Shutdown()
	assert.NoError(t, err)
	select {
	case err := <-errCh:
		assert.Error(t, err) // serve returns after listener is closed
	case <-time.After(time.Second):
		t.Fatal("serve did not stop after Shutdown")
	}
}

func TestListenAndServe_InvalidAddress(t *testing.T) {
	server := New(&Config{})
	err := server.ListenAndServe("tcp", "300.0.0.1:9999") // invalid IP
	assert.Error(t, err)
}

func TestHandleRequest_WithResolver(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer l.Close()
	lAddr := l.Addr().(*net.TCPAddr)

	go func() {
		conn, err2 := l.Accept()
		if err2 != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4)
		_, _ = io.ReadAtLeast(conn, buf, 4)
		_, _ = conn.Write([]byte("pong"))
	}()

	s := &Server{
		config: &Config{
			Resolver:        &resolver.DNSResolver{},
			DestConnTimeout: 2 * time.Second,
		},
	}

	req := &Request{
		Command: CommandConnect,
		DestAddr: &AddrSpec{
			FQDN: "localhost",
			Port: lAddr.Port,
		},
		BufferConn: bytes.NewReader([]byte("ping")),
	}
	req.realAddr = req.DestAddr

	conn := &MockConn{}
	_ = s.handleRequest(req, conn, nil)
}

func TestHandleRequest_ResolverError(t *testing.T) {
	s := &Server{
		config: &Config{
			Resolver: &mockFailResolver{},
		},
	}

	conn := &MockConn{}
	req := &Request{
		Command:  CommandConnect,
		DestAddr: &AddrSpec{FQDN: "bad.invalid", Port: 9999},
	}

	err := s.handleRequest(req, conn, nil)
	assert.Error(t, err)
}

type mockFailResolver struct{}

func (m *mockFailResolver) Resolve(_ string) (net.IP, error) {
	return nil, errors.New("resolve failed")
}

func TestHandleRequest_WithRewriter(t *testing.T) {
	s := &Server{
		config: &Config{
			Rewriter: &mockRewriter{},
		},
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

	conn := &MockConn{}
	req, err := NewRequest(buf)
	assert.NoError(t, err)
	req.realAddr = req.DestAddr
	// connection refused is expected — we just want to cover the Rewriter path
	_ = s.handleRequest(req, conn, nil)
}

type mockRewriter struct{}

func (m *mockRewriter) Rewrite(req *Request) *AddrSpec {
	return req.DestAddr
}
