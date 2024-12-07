package tor

import (
	"fmt"
	"golang.org/x/net/proxy"
	"net"
)

func Dial(network, addr string) (net.Conn, error) {
	dialer, err := proxy.SOCKS5("tcp", "localhost:9050", nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("failed to create tor dialer: %w", err)
	}

	return dialer.Dial(network, addr)
}
