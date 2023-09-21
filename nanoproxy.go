package main

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/ryanbekhen/nanoproxy/config"
	"github.com/ryanbekhen/nanoproxy/webproxy"
	"github.com/valyala/fasthttp"
	"os"
	"time"
	_ "time/tzdata"
)

func main() {
	cfg := config.New()
	loc, _ := time.LoadLocation(os.Getenv("TZ"))
	time.Local = loc

	logLevel := zerolog.InfoLevel
	if cfg.Debug {
		logLevel = zerolog.DebugLevel
	}

	logger := log.Level(logLevel).Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
		With().Timestamp().Logger()

	// validate protocol is http or https only
	if cfg.Proto != "http" && cfg.Proto != "https" {
		logger.Fatal().Msg("Protocol must be http or https")
	}

	srv := webproxy.New(cfg.BasicAuth, cfg.TunnelTimeout, logger)
	server := &fasthttp.Server{
		Handler: srv.Handler,
		Logger:  &logger,
	}

	logger.Info().Msg("Listening on " + cfg.Addr)
	if cfg.Proto == "https" {
		err := server.ListenAndServeTLS(cfg.Addr, cfg.PemPath, cfg.KeyPath)
		logger.Fatal().Msg("ListenAndServeTLS: " + err.Error())
	} else {
		err := server.ListenAndServe(cfg.Addr)
		logger.Fatal().Msg("ListenAndServe: " + err.Error())
	}
}
