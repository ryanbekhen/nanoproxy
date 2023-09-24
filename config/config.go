package config

import (
	"errors"
	"flag"
	"os"
	"strings"
	"time"
)

type Config struct {
	pemPath       string
	keyPath       string
	proto         string
	addr          string
	tunnelTimeout time.Duration
	basicAuth     string
	debug         bool
}

var (
	ErrInvalidProto     = errors.New("invalid protocol")
	ErrInvalidBasicAuth = errors.New("invalid basic auth")
)

func New() *Config {
	c := &Config{}
	flag.StringVar(&c.pemPath, "pem", "server.pem", "path to pem file")
	flag.StringVar(&c.keyPath, "key", "server.key", "path to key file")
	flag.StringVar(&c.proto, "proto", "http", "proxy protocol (http or https)")
	flag.StringVar(&c.addr, "addr", ":8080", "proxy listen address (default :8080)")
	flag.DurationVar(&c.tunnelTimeout, "timeout", time.Second*15, "tunnel timeout (default 15s)")
	flag.StringVar(&c.basicAuth, "auth", "", "basic auth (username:password)")
	flag.BoolVar(&c.debug, "debug", false, "debug mode")
	flag.Parse()

	if os.Getenv("PEM") != "" {
		c.pemPath = os.Getenv("PEM")
	}

	if os.Getenv("KEY") != "" {
		c.keyPath = os.Getenv("KEY")
	}

	if os.Getenv("PROTO") != "" {
		c.proto = os.Getenv("PROTO")
	}

	if os.Getenv("ADDR") != "" {
		c.addr = os.Getenv("ADDR")
	}

	if os.Getenv("TIMEOUT") != "" {
		d, err := time.ParseDuration(os.Getenv("TIMEOUT"))
		if err == nil {
			c.tunnelTimeout = d
		}
	}

	if os.Getenv("AUTH") != "" {
		c.basicAuth = os.Getenv("AUTH")
	}
	return c
}

func (c *Config) PemPath() string {
	return c.pemPath
}

func (c *Config) KeyPath() string {
	return c.keyPath
}

func (c *Config) Addr() string {
	return c.addr
}

func (c *Config) TunnelTimeout() time.Duration {
	return c.tunnelTimeout
}

func (c *Config) BasicAuth() map[string]string {
	cred := strings.Split(c.basicAuth, ",")
	users := map[string]string{}
	for _, cred := range cred {
		userPass := strings.Split(cred, ":")
		if len(userPass) == 2 {
			users[userPass[0]] = userPass[1]
		}
	}
	return users
}

func (c *Config) Debug() bool {
	return c.debug
}

func (c *Config) IsHTTPS() bool {
	return c.proto == "https"
}

func (c *Config) Validate() error {
	if c.proto != "http" && c.proto != "https" {
		return ErrInvalidProto
	}

	if c.basicAuth != "" {
		if len(c.BasicAuth()) == 0 {
			return ErrInvalidBasicAuth
		}
	}

	return nil
}
