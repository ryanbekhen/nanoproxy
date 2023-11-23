package socks5

import (
	"testing"

	"context"
)

func TestPermitCommand(t *testing.T) {
	ctx := context.Background()
	r := &PermitCommand{true, false, false}

	if _, ok := r.Allow(ctx, &Request{Command: ConnectCommand}); !ok {
		t.Fatalf("expect connect")
	}

	if _, ok := r.Allow(ctx, &Request{Command: BindCommand}); ok {
		t.Fatalf("do not expect bind")
	}

	if _, ok := r.Allow(ctx, &Request{Command: AssociateCommand}); ok {
		t.Fatalf("do not expect associate")
	}
}

func TestPermitAll(t *testing.T) {
	ctx := context.Background()
	r := PermitAll()

	if _, ok := r.Allow(ctx, &Request{Command: ConnectCommand}); !ok {
		t.Fatalf("expect connect")
	}

	if _, ok := r.Allow(ctx, &Request{Command: BindCommand}); !ok {
		t.Fatalf("expect bind")
	}

	if _, ok := r.Allow(ctx, &Request{Command: AssociateCommand}); !ok {
		t.Fatalf("expect associate")
	}
}

func TestPermitNone(t *testing.T) {
	ctx := context.Background()
	r := PermitNone()

	if _, ok := r.Allow(ctx, &Request{Command: ConnectCommand}); ok {
		t.Fatalf("do not expect connect")
	}

	if _, ok := r.Allow(ctx, &Request{Command: BindCommand}); ok {
		t.Fatalf("do not expect bind")
	}

	if _, ok := r.Allow(ctx, &Request{Command: AssociateCommand}); ok {
		t.Fatalf("do not expect associate")
	}
}

func TestPermitUnsupported(t *testing.T) {
	ctx := context.Background()
	r := &PermitCommand{false, false, false}

	if _, ok := r.Allow(ctx, &Request{Command: 0x42}); ok {
		t.Fatalf("do not expect unsupported")
	}
}
