package main

import (
	"github.com/caarlos0/env/v10"
	"github.com/rs/zerolog"
	"github.com/ryanbekhen/nanoproxy/pkg/config"
	"github.com/ryanbekhen/nanoproxy/pkg/socks5"
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

	socks5Config := &socks5.Config{
		Logger: &logger,
	}

	sock5Server, err := socks5.New(socks5Config)
	if err != nil {
		logger.Fatal().Msg(err.Error())
	}

	logger.Info().Msgf("Starting socks5 server on %s://%s", cfg.Network, cfg.ADDR)
	if err := sock5Server.ListenAndServe(cfg.Network, cfg.ADDR); err != nil {
		logger.Fatal().Msg(err.Error())
	}
}
