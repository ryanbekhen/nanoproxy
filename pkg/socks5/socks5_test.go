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
	"github.com/ryanbekhen/nanoproxy/pkg/traffic"
	"github.com/stretchr/testify/assert"
)

type resolverFunc func(host string) (net.IP, error)

func (f resolverFunc) Resolve(host string) (net.IP, error) {
	return f(host)
}

func parseJSONLogLines(t *testing.T, buf *bytes.Buffer) []map[string]interface{} {
	t.Helper()

	content := bytes.TrimSpace(buf.Bytes())
	if len(content) == 0 {
		return nil
	}

	lines := bytes.Split(content, []byte("\n"))
	entries := make([]map[string]interface{}, 0, len(lines))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		entry := map[string]interface{}{}
		if err := json.Unmarshal(line, &entry); err != nil {
			t.Fatalf("failed to parse log entry: %v", err)
		}
		entries = append(entries, entry)
	}

	return entries
}

func parseLastJSONLogLine(t *testing.T, buf *bytes.Buffer) map[string]interface{} {
	t.Helper()

	entries := parseJSONLogLines(t, buf)
	if len(entries) == 0 {
		t.Fatal("expected log output")
	}

	return entries[len(entries)-1]
}

// testHandleConnect wraps handleConnect for tests that use the old signature
func (s *Server) testHandleConnect(conn net.Conn, req *Request) error {
	tracker := traffic.NewTracker()
	session := tracker.Start("test", "127.0.0.1")
	defer session.Close()
	logger := zerolog.New(io.Discard)
	reqLogger := logger.With().
		Str("protocol", "socks5").
		Str("command", req.Command.String()).
		Str("dest_addr", req.DestAddr.String()).
		Logger()
	return s.handleConnect(conn, req, session, reqLogger)
}

// testHandleRequest wraps handleRequest for tests that use the old signature
func (s *Server) testHandleRequest(req *Request, conn net.Conn) error {
	tracker := traffic.NewTracker()
	session := tracker.Start("test", "127.0.0.1")
	defer session.Close()
	logger := zerolog.New(io.Discard)
	reqLogger := logger.With().
		Str("protocol", "socks5").
		Str("command", req.Command.String()).
		Str("dest_addr", req.DestAddr.String()).
		Logger()
	return s.handleRequest(req, conn, session, reqLogger)
}

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

	entry := parseLastJSONLogLine(t, &logBuf)
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

	entry := parseLastJSONLogLine(t, &logBuf)
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

	entry := parseLastJSONLogLine(t, &logBuf)
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

func TestHandleConnection_LogsSuccessfulRequestAtInfo(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer backend.Close()

	go func() {
		conn, acceptErr := backend.Accept()
		assert.NoError(t, acceptErr)
		if acceptErr != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 4)
		_, _ = io.ReadFull(conn, buf)
		_, _ = conn.Write([]byte("pong"))
	}()

	var logBuf bytes.Buffer
	logger := zerolog.New(&logBuf).Level(zerolog.InfoLevel)
	server := New(&Config{
		Authentication: []Authenticator{&NoAuthAuthenticator{}},
		Logger:         &logger,
		Tracker:        traffic.NewTracker(),
	})

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		server.handleConnection(serverConn)
	}()

	backendAddr := backend.Addr().(*net.TCPAddr)
	request := bytes.NewBuffer(nil)
	request.Write([]byte{Version})
	request.Write([]byte{1, NoAuth.Uint8()})
	request.Write([]byte{Version, CommandConnect.Uint8(), 0, AddressTypeIPv4.Uint8()})
	request.Write([]byte{127, 0, 0, 1})
	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(backendAddr.Port))
	request.Write(port)
	request.Write([]byte("ping"))

	_, err = clientConn.Write(request.Bytes())
	assert.NoError(t, err)

	response := make([]byte, 16)
	_, err = io.ReadFull(clientConn, response)
	assert.NoError(t, err)
	_ = clientConn.Close()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for connection handler")
	}

	entry := parseLastJSONLogLine(t, &logBuf)
	assert.Equal(t, "request completed", entry["message"])
	assert.Equal(t, "info", entry["level"])
	assert.Equal(t, "socks5", entry["protocol"])
	assert.Equal(t, "connect", entry["command"])
	assert.Equal(t, "anonymous", entry["username"])
	assert.Equal(t, fmt.Sprintf("127.0.0.1:%d", backendAddr.Port), entry["dest_addr"])
	assert.NotEmpty(t, entry["latency"])
	assert.Equal(t, float64(4), entry["upload_bytes"])
	assert.Equal(t, float64(4), entry["download_bytes"])
}

func TestHandleConnection_LogsSuccessfulRequestDetailsAtDebug(t *testing.T) {
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer backend.Close()

	go func() {
		conn, acceptErr := backend.Accept()
		assert.NoError(t, acceptErr)
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(io.Discard, conn)
	}()

	var logBuf bytes.Buffer
	logger := zerolog.New(&logBuf).Level(zerolog.DebugLevel)
	server := New(&Config{
		Authentication: []Authenticator{&NoAuthAuthenticator{}},
		Logger:         &logger,
		Tracker:        traffic.NewTracker(),
		Resolver: resolverFunc(func(host string) (net.IP, error) {
			return net.ParseIP("127.0.0.1"), nil
		}),
	})

	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		server.handleConnection(serverConn)
	}()

	backendAddr := backend.Addr().(*net.TCPAddr)
	request := bytes.NewBuffer(nil)
	request.Write([]byte{Version})
	request.Write([]byte{1, NoAuth.Uint8()})
	request.Write([]byte{Version, CommandConnect.Uint8(), 0, AddressTypeDomain.Uint8(), 17})
	request.WriteString("debug-target.test")
	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(backendAddr.Port))
	request.Write(port)

	_, err = clientConn.Write(request.Bytes())
	assert.NoError(t, err)

	response := make([]byte, 12)
	_, err = io.ReadFull(clientConn, response)
	assert.NoError(t, err)
	_ = clientConn.Close()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for connection handler")
	}

	entries := parseJSONLogLines(t, &logBuf)
	assert.GreaterOrEqual(t, len(entries), 4)
	assert.Equal(t, "connection accepted without authentication", entries[0]["message"])
	assert.Equal(t, "request received", entries[1]["message"])
	assert.Equal(t, "resolved destination address", entries[2]["message"])
	assert.Equal(t, "127.0.0.1", entries[2]["resolved_ip"])
	assert.Equal(t, "dialing destination", entries[3]["message"])
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
	err = s.testHandleConnect(resp, req)
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
	err = s.testHandleConnect(resp, req)
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
	err = s.testHandleConnect(resp, req)
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
	err := s.testHandleRequest(req, resp)
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
	_ = s.testHandleRequest(req, conn)
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

	err := s.testHandleRequest(req, conn)
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
	_ = s.testHandleRequest(req, conn)
}

type mockRewriter struct{}

func (m *mockRewriter) Rewrite(req *Request) *AddrSpec {
	return req.DestAddr
}
