package socks5

import (
	"testing"
)

func TestStaticCredentials(t *testing.T) {
	credentials := StaticCredentials{
		"foo": "bar",
		"baz": "",
	}

	if !credentials.Valid("foo", "bar") {
		t.Fatalf("expect valid")
	}

	if !credentials.Valid("baz", "") {
		t.Fatalf("expect valid")
	}

	if credentials.Valid("foo", "") {
		t.Fatalf("expect invalid")
	}
}

func TestStaticCredentials_Empty(t *testing.T) {
	credentials := StaticCredentials{}

	if credentials.Valid("foo", "bar") {
		t.Fatalf("expect invalid")
	}
}
