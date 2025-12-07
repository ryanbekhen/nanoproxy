package socks5

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

type AddressRewriter interface {
	Rewrite(request *Request) *AddrSpec
}

// AddrSpec is a SOCKS5 address specification
type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

// String returns a string representation of the address
func (a *AddrSpec) String() string {
	if a.FQDN != "" {
		return fmt.Sprintf("%s (%s):%d", a.FQDN, a.IP, a.Port)
	}
	// Check if the address is an IPv6 address
	if strings.Count(a.IP.String(), ":") > 1 {
		return fmt.Sprintf("[%s]:%d", a.IP, a.Port)
	}
	return fmt.Sprintf("%s:%d", a.IP, a.Port)
}

// Address returns a string suitable to dial; prefer returning IP-based
// address, fallback to FQDN
func (a *AddrSpec) Address() string {
	if 0 != len(a.IP) {
		return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
	}
	return net.JoinHostPort(a.FQDN, strconv.Itoa(a.Port))
}

// Request is a SOCKS5 request message
type Request struct {
	Version     uint8
	Command     Command
	AuthContext *Context
	RemoteAddr  *AddrSpec
	DestAddr    *AddrSpec
	realAddr    *AddrSpec
	BufferConn  io.Reader
	Latency     time.Duration
}

func NewRequest(bufferConn io.Reader) (*Request, error) {
	header := []byte{0, 0, 0}
	n, err := io.ReadAtLeast(bufferConn, header, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	if n < 1 {
		return nil, fmt.Errorf("header too short, expected at least 1 byte")
	}

	if header[0] != Version {
		return nil, fmt.Errorf("unsupported version: %d", header[0])
	}

	dest, err := readAddressSpec(bufferConn)
	if err != nil {
		return nil, err
	}

	request := &Request{
		Version:    Version,
		Command:    Command(header[1]),
		BufferConn: bufferConn,
		DestAddr:   dest,
	}

	return request, nil
}

func readAddressSpec(r io.Reader) (*AddrSpec, error) {
	d := &AddrSpec{}

	addrType := []byte{0}
	if _, err := r.Read(addrType); err != nil {
		return nil, err
	}

	// Handle on a per-type basis
	switch AddrType(addrType[0]) {
	case AddressTypeIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.IP = addr

	case AddressTypeIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadAtLeast(r, addr, len(addr)); err != nil {
			return nil, err
		}
		d.IP = addr

	case AddressTypeDomain:
		if _, err := r.Read(addrType); err != nil {
			return nil, err
		}
		addrLen := int(addrType[0])
		fqdn := make([]byte, addrLen)
		if _, err := io.ReadAtLeast(r, fqdn, addrLen); err != nil {
			return nil, err
		}
		d.FQDN = string(fqdn)

	default:
		return nil, fmt.Errorf("unrecognized address type: %d", addrType[0])
	}

	// Read the port
	port := []byte{0, 0}
	if _, err := io.ReadAtLeast(r, port, 2); err != nil {
		return nil, err
	}
	d.Port = (int(port[0]) << 8) | int(port[1])

	return d, nil
}

func sendReply(conn io.Writer, reply uint8, addr *AddrSpec) error {
	var addrType uint8
	var addrBody []byte
	var addrPort uint16
	switch {
	case addr == nil:
		addrType = AddressTypeIPv4.Uint8()
		addrBody = []byte{0, 0, 0, 0}
		addrPort = 0

	case addr.FQDN != "":
		addrType = AddressTypeDomain.Uint8()
		addrBody = append([]byte{byte(len(addr.FQDN))}, addr.FQDN...)
		if addr.Port < 0 || addr.Port > 65535 {
			return fmt.Errorf("port value out of range uint16: %d", addr.Port)
		}
		addrPort = uint16(addr.Port)

	case addr.IP.To4() != nil:
		addrType = AddressTypeIPv4.Uint8()
		addrBody = addr.IP.To4()
		if addr.Port < 0 || addr.Port > 65535 {
			return fmt.Errorf("port value out of range uint16: %d", addr.Port)
		}
		addrPort = uint16(addr.Port)

	case addr.IP.To16() != nil:
		addrType = AddressTypeIPv6.Uint8()
		addrBody = addr.IP.To16()
		if addr.Port < 0 || addr.Port > 65535 {
			return fmt.Errorf("port value out of range uint16: %d", addr.Port)
		}
		addrPort = uint16(addr.Port)

	default:
		return fmt.Errorf("unrecognized address type")
	}

	// Format the message
	msg := make([]byte, 6+len(addrBody))
	msg[0] = Version
	msg[1] = reply
	msg[2] = 0 // Reserved
	msg[3] = addrType
	copy(msg[4:], addrBody)
	msg[4+len(addrBody)] = byte(addrPort >> 8)
	msg[4+len(addrBody)+1] = byte(addrPort & 0xff)

	// Send the message
	_, err := conn.Write(msg)

	return err
}

func relay(dst io.Writer, src io.Reader, errCh chan error) {
	_, err := io.Copy(dst, src)
	if tcpConn, ok := dst.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
	}
	errCh <- err
}
