package main

import (
	"crypto/tls"
	"github.com/ryanbekhen/nanoproxy/config"
	"github.com/ryanbekhen/nanoproxy/proxy"
	"log"
	"net/http"
	"os"
	"time"
	_ "time/tzdata"
)

func main() {
	cfg := config.New()
	loc, _ := time.LoadLocation(os.Getenv("TZ"))
	time.Local = loc

	// validate protocol is http or https only
	if cfg.Proto != "http" && cfg.Proto != "https" {
		log.Fatal("Protocol must be http or https")
	}

	srv := proxy.New(cfg.TunnelTimeout)
	server := &http.Server{
		Addr:              cfg.Addr,
		Handler:           srv,
		ReadHeaderTimeout: 15 * time.Second,

		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	// start server with TLS if protocol is https otherwise start server without TLS (http)
	if cfg.Proto == "https" {
		log.Fatal(server.ListenAndServeTLS(cfg.PemPath, cfg.KeyPath))
	} else {
		log.Fatal(server.ListenAndServe())
	}
}
