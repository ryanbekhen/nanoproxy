package socks5

import (
	"context"
	"net"
)

// NameResolver is used to implement custom name resolution
type NameResolver interface {
	Resolve(ctx context.Context, address string) (context.Context, net.IP, error)
}

// DNSResolver uses the system DNS to resolve host names
type DNSResolver struct{}

func (d DNSResolver) Resolve(ctx context.Context, address string) (context.Context, net.IP, error) {
	addr, err := net.ResolveIPAddr("ip", address)
	if err != nil {
		return ctx, nil, err
	}
	return ctx, addr.IP, err
}
