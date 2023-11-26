package socks5

import (
	"net"
)

type Resolver interface {
	Resolve(destAddr string) (net.IP, error)
}

type DNSResolver struct{}

func (d *DNSResolver) Resolve(destAddr string) (net.IP, error) {
	addr, err := net.ResolveIPAddr("ip", destAddr)
	if err != nil {
		return nil, err
	}

	return addr.IP, err
}
