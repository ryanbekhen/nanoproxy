package config

import (
	"flag"
	"os"
	"time"
)

type Config struct {
	PemPath       string
	KeyPath       string
	Proto         string
	Addr          string
	TunnelTimeout time.Duration
	BasicAuth     string
}

func New() *Config {
	c := &Config{}
	flag.StringVar(&c.PemPath, "pem", "server.pem", "path to pem file")
	flag.StringVar(&c.KeyPath, "key", "server.key", "path to key file")
	flag.StringVar(&c.Proto, "proto", "http", "proxy protocol (http or https)")
	flag.StringVar(&c.Addr, "addr", ":8080", "proxy listen address (default :8080)")
	flag.DurationVar(&c.TunnelTimeout, "timeout", time.Second*15, "tunnel timeout (default 15s)")
	flag.StringVar(&c.BasicAuth, "auth", "", "basic auth (username:password)")
	flag.Parse()

	if os.Getenv("PEM") != "" {
		c.PemPath = os.Getenv("PEM")
	}

	if os.Getenv("KEY") != "" {
		c.KeyPath = os.Getenv("KEY")
	}

	if os.Getenv("PROTO") != "" {
		c.Proto = os.Getenv("PROTO")
	}

	if os.Getenv("ADDR") != "" {
		c.Addr = os.Getenv("ADDR")
	}

	if os.Getenv("TIMEOUT") != "" {
		d, err := time.ParseDuration(os.Getenv("TIMEOUT"))
		if err == nil {
			c.TunnelTimeout = d
		}
	}

	if os.Getenv("AUTH") != "" {
		c.BasicAuth = os.Getenv("AUTH")
	}
	return c
}
