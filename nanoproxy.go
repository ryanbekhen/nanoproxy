package main

import (
	"github.com/caarlos0/env/v10"
	"github.com/rs/zerolog"
	"github.com/ryanbekhen/nanoproxy/pkg/config"
	"github.com/ryanbekhen/nanoproxy/pkg/socks5"
	"github.com/ryanbekhen/nanoproxy/pkg/tor"
	"os"
	"strings"
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
		DestConnTimeout:   cfg.DestTimeout,
		ClientConnTimeout: cfg.ClientTimeout,
		Resolver:          &socks5.DNSResolver{},
	}

	credentials := socks5.StaticCredentialStore{}
	for _, cred := range cfg.Credentials {
		credArr := strings.Split(cred, ":")
		if len(credArr) != 2 {
			logger.Fatal().Msgf("Invalid credential: %s", cred)
		}
		credentials[credArr[0]] = credArr[1]
	}
	if len(credentials) > 0 {
		socks5Config.Credentials = credentials
	}

	if cfg.TorEnabled {
		torDialer := &tor.DefaultDialer{}
		socks5Config.Dial = torDialer.Dial
		logger.Info().Msg("Tor mode enabled")

		torController := tor.NewTorController(torDialer)
		ch := make(chan bool)
		go tor.SwitcherIdentity(&logger, torController, cfg.TorIdentityInterval, ch)

		go func() {
			<-ch
			logger.Fatal().Msg("Tor identity switcher stopped")
		}()
	}

	sock5Server := socks5.New(&socks5Config)

	logger.Info().Msgf("Starting socks5 server on %s://%s", cfg.Network, cfg.ADDR)
	if err := sock5Server.ListenAndServe(cfg.Network, cfg.ADDR); err != nil {
		logger.Fatal().Msg(err.Error())
	}
}
