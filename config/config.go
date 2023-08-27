package config

import (
	"flag"
	"time"
)

type Config struct {
	PemPath       string
	KeyPath       string
	Proto         string
	Addr          string
	TunnelTimeout time.Duration
}

func New() *Config {
	c := &Config{}
	flag.StringVar(&c.PemPath, "pem", "server.pem", "path to pem file")
	flag.StringVar(&c.KeyPath, "key", "server.key", "path to key file")
	flag.StringVar(&c.Proto, "proto", "http", "proxy protocol (http or https)")
	flag.StringVar(&c.Addr, "addr", ":8080", "proxy listen address (default :8080)")
	flag.DurationVar(&c.TunnelTimeout, "timeout", time.Second*15, "tunnel timeout (default 15s)")
	flag.Parse()
	return c
}
