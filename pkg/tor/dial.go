package tor

import (
	"net"

	"golang.org/x/net/proxy"
)

var customSOCKS5 = proxy.SOCKS5

type Dialer interface {
	Dial(network, address string) (net.Conn, error)
	DialControlPort(network, address string) (net.Conn, error)
}

type DefaultDialer struct{}

func (d DefaultDialer) Dial(network, address string) (net.Conn, error) {
	dialer, _ := customSOCKS5("tcp", "localhost:9050", nil, proxy.Direct)
	return dialer.Dial(network, address)
}

func (d DefaultDialer) DialControlPort(network, address string) (net.Conn, error) {
	return net.Dial(network, address)
}
