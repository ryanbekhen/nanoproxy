package tor

import (
	"fmt"
	"golang.org/x/net/proxy"
	"net"
)

var customSOCKS5 = proxy.SOCKS5

type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

type DefaultDialer struct{}

func (d DefaultDialer) Dial(network, address string) (net.Conn, error) {
	dialer, err := customSOCKS5("tcp", "localhost:9050", nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to create tor dialer: %w", err)
	}

	return dialer.Dial(network, address)
}
