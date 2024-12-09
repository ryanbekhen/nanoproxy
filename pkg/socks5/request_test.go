package socks5

import (
	"bytes"
	"encoding/binary"
	"github.com/stretchr/testify/assert"
	"io"
	"net"
	"testing"
	"time"
)

type MockConn struct {
	net.Conn
	buf bytes.Buffer
}

func (m *MockConn) Read(b []byte) (n int, err error) {
	return m.buf.Read(b)
}

func (m *MockConn) Write(b []byte) (n int, err error) {
	return m.buf.Write(b)
}

func (m *MockConn) Close() error {
	return nil
}

func (m *MockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (m *MockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

func (m *MockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *MockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *MockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func Test_AddrSpec_String(t *testing.T) {
	var a *AddrSpec
	a = &AddrSpec{
		FQDN: "www.google.com",
		IP:   net.ParseIP("192.168.1.1"),
		Port: 8080,
	}

	assert.Equal(t, "www.google.com (192.168.1.1):8080", a.String())

	a = &AddrSpec{
		FQDN: "",
		IP:   net.ParseIP("192.168.1.1"),
		Port: 8080,
	}

	assert.Equal(t, "192.168.1.1:8080", a.String())
}

func Test_NewRequest(t *testing.T) {
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

		if !bytes.Equal(buf, []byte("ping")) {
			assert.Fail(t, "expected ping, got %s", string(buf))
		}

		_, _ = conn.Write([]byte("pong"))
	}()
	lAddr := l.Addr().(*net.TCPAddr)
	s := &Server{
		config: &Config{
			Resolver: &DNSResolver{},
		},
	}

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
	assert.NoError(t, err)
	assert.NotNil(t, req)

	err = s.handleRequest(req, resp)
	assert.NoError(t, err)

	// verify the response
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

	// Ignore the port
	out[8] = 0
	out[9] = 0

	assert.Equal(t, expected, out)
}

func Test_NewRequest_InvalidVersion(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{4, 1, 0, 1, 127, 0, 0, 1, 0, 0})

	_, err := NewRequest(buf)
	assert.Error(t, err)
}

func Test_NewRequest_InvalidReadAddressSpec(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{5, 1, 0, 1, 127, 0, 0, 1, 0})

	_, err := NewRequest(buf)
	assert.Error(t, err)
}

func Test_ReadAddressSpec_AddressTypeIPv4(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{1, 127, 0, 0, 1, 0, 0})

	addr, err := readAddressSpec(buf)
	assert.NoError(t, err)
	assert.NotNil(t, addr)
	assert.Equal(t, "127.0.0.1:0", addr.String())
}

func Test_ReadAddressSpec_AddressTypeIPv6(t *testing.T) {
	// ipv6 address: 2001:db8:85a3::8a2e:370:7334 (port: 8080)
	buffer := bytes.NewBuffer([]byte{0x04, 0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34, 0x1f, 0x90})
	addr, err := readAddressSpec(buffer)
	assert.NoError(t, err)
	assert.NotNil(t, addr)
	assert.Equal(t, "2001:db8:85a3::8a2e:370:7334", addr.IP.String())
	assert.Equal(t, 8080, addr.Port)
}

func Test_ReadAddressSpec_AddressTypeDomain(t *testing.T) {
	// domain: www.google.com (port: 8333)
	buffer := bytes.NewBuffer([]byte{0x03, 0x0e, 0x77, 0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x20, 0x8d})
	addr, err := readAddressSpec(buffer)
	assert.NoError(t, err)
	assert.NotNil(t, addr)
	assert.Equal(t, "www.google.com", addr.FQDN)
	assert.Equal(t, 8333, addr.Port)
}

func Test_ReadAddressSpec_InvalidAddressType(t *testing.T) {
	buf := bytes.NewBuffer(nil)
	buf.Write([]byte{0x05, 0x0e, 0x77, 0x77, 0x77})

	_, err := readAddressSpec(buf)
	assert.Error(t, err)
}

func TestSendReply(t *testing.T) {
	buf := new(bytes.Buffer)

	addr := &AddrSpec{
		FQDN: "localhost",
		IP:   net.ParseIP("127.0.0.1"),
		Port: 8080,
	}

	err := sendReply(buf, AuthSuccess.Uint8(), addr)
	assert.NoError(t, err)

	expected := []byte{
		Version,                   // SOCKS5 version
		AuthSuccess.Uint8(),       // Reply code
		0,                         // Reserved field
		AddressTypeDomain.Uint8(), // Address type
		byte(len(addr.FQDN)),      // Length of FQDN
	}
	expected = append(expected, addr.FQDN...)
	expected = append(expected, byte(addr.Port>>8), byte(addr.Port))

	assert.Equal(t, expected, buf.Bytes())
}

func TestSendReply_IPv6(t *testing.T) {
	// Create a bytes.Buffer to capture the output
	buf := new(bytes.Buffer)

	// Create an AddrSpec with an IPv6 address
	addr := &AddrSpec{
		IP:   net.ParseIP("2001:db8:85a3::8a2e:370:7334"),
		Port: 8080,
	}

	// Call sendReply
	err := sendReply(buf, AuthSuccess.Uint8(), addr)
	assert.NoError(t, err)

	// Prepare the expected output
	expected := []byte{
		Version,                 // SOCKS5 version
		AuthSuccess.Uint8(),     // Reply code
		0,                       // Reserved field
		AddressTypeIPv6.Uint8(), // Address type
	}
	expected = append(expected, addr.IP...)                          // IPv6 address
	expected = append(expected, byte(addr.Port>>8), byte(addr.Port)) // Port

	// Compare the output with the expected output
	assert.Equal(t, expected, buf.Bytes())
}

func TestSendReply_InvalidAddressType(t *testing.T) {
	buf := new(bytes.Buffer)
	addr := &AddrSpec{
		Port: 8080,
	}
	err := sendReply(buf, AuthSuccess.Uint8(), addr)
	assert.Error(t, err)
}

func TestSendReply_AddrNil(t *testing.T) {
	// Create a bytes.Buffer to capture the output
	buf := new(bytes.Buffer)

	// Call sendReply with nil AddrSpec
	err := sendReply(buf, AuthSuccess.Uint8(), nil)
	assert.NoError(t, err)

	// Prepare the expected output
	expected := []byte{
		Version,                 // SOCKS5 version
		AuthSuccess.Uint8(),     // Reply code
		0,                       // Reserved field
		AddressTypeIPv4.Uint8(), // Address type
		0, 0, 0, 0,              // IP address (0.0.0.0)
		0, 0, // Port (0)
	}

	// Compare the output with the expected output
	assert.Equal(t, expected, buf.Bytes())
}
