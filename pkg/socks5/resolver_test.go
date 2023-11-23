package socks5

import (
	"testing"

	"context"
)

func TestDNSResolver(t *testing.T) {
	d := DNSResolver{}
	ctx := context.Background()

	_, addr, err := d.Resolve(ctx, "localhost")
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	if !addr.IsLoopback() {
		t.Fatalf("expected loopback")
	}
}

func TestDNSResolver_Invalid(t *testing.T) {
	d := DNSResolver{}
	ctx := context.Background()

	_, _, err := d.Resolve(ctx, "invalid.invalid")
	if err == nil {
		t.Fatalf("expected error")
	}
}
