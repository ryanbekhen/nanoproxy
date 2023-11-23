package socks5

import (
	"bytes"
	"encoding/binary"
	"github.com/rs/zerolog"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

type MockConn struct {
	buf bytes.Buffer
}

func (m *MockConn) Write(b []byte) (int, error) {
	return m.buf.Write(b)
}

func (m *MockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: []byte{127, 0, 0, 1}, Port: 65432}
}

func TestRequest_Connect(t *testing.T) {
	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Errorf("err: %v", err)
			return
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadAtLeast(conn, buf, 4); err != nil {
			t.Errorf("err: %v", err)
			return
		}

		if !bytes.Equal(buf, []byte("ping")) {
			t.Errorf("bad: %v", buf)
			return
		}
		conn.Write([]byte("pong"))
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	// Make server
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).With().Timestamp().Logger()
	s := &Server{config: &Config{
		Rules:    PermitAll(),
		Resolver: DNSResolver{},
		Logger:   &logger,
	}}

	// Create the connect request
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	buf.Write(port)

	// Send a ping
	buf.Write([]byte("ping"))

	// Handle the request
	resp := &MockConn{}
	req, err := NewRequest(buf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := s.handleRequest(req, resp); err != nil {
		t.Fatalf("err: %v", err)
	}

	// Verify response
	out := resp.buf.Bytes()
	expected := []byte{
		5,
		0,
		0,
		1,
		127, 0, 0, 1,
		0, 0,
		'p', 'o', 'n', 'g',
	}

	// Ignore the port for both
	out[8] = 0
	out[9] = 0

	if !bytes.Equal(out, expected) {
		t.Fatalf("bad: %v %v", out, expected)
	}
}

func TestRequest_Connect_RuleFail(t *testing.T) {
	// Create a local listener
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Errorf("err: %v", err)
			return
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadAtLeast(conn, buf, 4); err != nil {
			t.Errorf("err: %v", err)
			return
		}

		if !bytes.Equal(buf, []byte("ping")) {
			t.Errorf("bad: %v", buf)
			return
		}
		conn.Write([]byte("pong"))
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	// Make server
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).With().Timestamp().Logger()
	s := &Server{config: &Config{
		Rules:    PermitNone(),
		Resolver: DNSResolver{},
		Logger:   &logger,
	}}

	// Create the connect request
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1})

	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	buf.Write(port)

	// Send a ping
	buf.Write([]byte("ping"))

	// Handle the request
	resp := &MockConn{}
	req, err := NewRequest(buf)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if err := s.handleRequest(req, resp); !strings.Contains(err.Error(), "blocked by rules") {
		t.Fatalf("err: %v", err)
	}

	// Verify response
	out := resp.buf.Bytes()
	expected := []byte{
		5,
		2,
		0,
		1,
		0, 0, 0, 0,
		0, 0,
	}

	if !bytes.Equal(out, expected) {
		t.Fatalf("bad: %v %v", out, expected)
	}
}

func TestCommandToString(t *testing.T) {
	if CommandToString(ConnectCommand) != "connect" {
		t.Fatal("bad")
	} else if CommandToString(BindCommand) != "bind" {
		t.Fatal("bad")
	} else if CommandToString(AssociateCommand) != "associate" {
		t.Fatal("bad")
	} else if CommandToString(0) != "unknown" {
		t.Fatal("bad")
	}
}