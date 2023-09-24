package main

import (
	"github.com/gofiber/contrib/fiberzerolog"
	"github.com/gofiber/fiber/v2"
	recoverFiber "github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/ryanbekhen/nanoproxy/config"
	"github.com/ryanbekhen/nanoproxy/middleware/basicauth"
	"github.com/ryanbekhen/nanoproxy/middleware/hopbyhop"
	"github.com/ryanbekhen/nanoproxy/webproxy"
	"os"
	"time"
	_ "time/tzdata"
)

func main() {
	cfg := config.New()
	loc, _ := time.LoadLocation(os.Getenv("TZ"))
	time.Local = loc

	logLevel := zerolog.InfoLevel
	if cfg.Debug() {
		logLevel = zerolog.DebugLevel
	}

	logger := log.Level(logLevel).Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
		With().Timestamp().Logger()

	// validate config
	if err := cfg.Validate(); err != nil {
		logger.Fatal().Msg(err.Error())
	}

	server := fiber.New(fiber.Config{DisableStartupMessage: true})
	srv := webproxy.New(cfg.TunnelTimeout())

	// middleware
	server.Use(recoverFiber.New())
	server.Use(basicauth.New(basicauth.Config{Users: cfg.BasicAuth()}))
	server.Use(hopbyhop.New())
	server.Use(fiberzerolog.New(fiberzerolog.Config{
		Logger: &logger,
		Fields: []string{"ip", "latency", "status", "url", "error"},
	}))

	// routes
	server.All("*", srv.Handler)

	// start server
	logger.Info().Msgf("Starting server on %s", cfg.Addr())
	if cfg.IsHTTPS() {
		logger.Fatal().
			Err(server.ListenTLS(cfg.Addr(), cfg.PemPath(), cfg.KeyPath())).
			Msg("Server closed")
	} else {
		logger.Fatal().
			Err(server.Listen(cfg.Addr())).
			Msg("Server closed")
	}
}
