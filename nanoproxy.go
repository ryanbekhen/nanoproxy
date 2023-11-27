package main

import (
	"github.com/caarlos0/env/v10"
	"github.com/rs/zerolog"
	"github.com/ryanbekhen/nanoproxy/pkg/config"
	"github.com/ryanbekhen/nanoproxy/pkg/socks5"
	"net"
	"os"
	"time"

	_ "time/tzdata"
)

func main() {
	cfg := &config.Config{}
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).With().Timestamp().Logger()

	if err := env.Parse(cfg); err != nil {
		logger.Fatal().Msg(err.Error())
	}

	loc, _ := time.LoadLocation(cfg.Timezone)
	if loc != nil {
		time.Local = loc
	}

	socks5Config := socks5.Config{
		Logger:            &logger,
		Resolver:          &socks5.DNSResolver{},
		ClientConnTimeout: cfg.ClientTimeout,
		DestConnTimeout:   cfg.DestTimeout,
		AfterRequest: func(req *socks5.Request, conn net.Conn) {
			logger.Info().
				Str("client_addr", conn.RemoteAddr().String()).
				Str("dest_addr", req.DestAddr.String()).
				Str("latency", req.Latency.String()).
				Msg("request processed")
		},
	}

	sock5Server := socks5.New(&socks5Config)

	logger.Info().Msgf("Starting socks5 server on %s://%s", cfg.Network, cfg.ADDR)
	if err := sock5Server.ListenAndServe(cfg.Network, cfg.ADDR); err != nil {
		logger.Fatal().Msg(err.Error())
	}
}
