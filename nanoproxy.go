package main

import (
	"github.com/caarlos0/env/v10"
	"github.com/rs/zerolog"
	"github.com/ryanbekhen/nanoproxy/pkg/config"
	"github.com/ryanbekhen/nanoproxy/pkg/credential"
	"github.com/ryanbekhen/nanoproxy/pkg/httpproxy"
	"github.com/ryanbekhen/nanoproxy/pkg/resolver"
	"github.com/ryanbekhen/nanoproxy/pkg/socks5"
	"github.com/ryanbekhen/nanoproxy/pkg/tor"
	"net"
	"net/http"
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

	var credentials credential.Store
	if len(cfg.Credentials) > 0 {
		credentials := credential.NewStaticCredentialStore()
		for _, cred := range cfg.Credentials {
			credArr := strings.Split(cred, ":")
			if len(credArr) != 2 {
				logger.Fatal().Msgf("Invalid credential: %s", cred)
			}

			credentials.Add(credArr[0], credArr[1])
		}
	}

	dnsResolver := &resolver.DNSResolver{}

	httpConfig := httpproxy.Config{
		Credentials:       credentials,
		Logger:            &logger,
		DestConnTimeout:   cfg.DestTimeout,
		ClientConnTimeout: cfg.ClientTimeout,
		Dial:              net.Dial,
		Resolver:          dnsResolver,
	}

	httpServer := httpproxy.New(&httpConfig)

	socks5Config := socks5.Config{
		Logger:            &logger,
		DestConnTimeout:   cfg.DestTimeout,
		ClientConnTimeout: cfg.ClientTimeout,
		Resolver:          dnsResolver,
	}

	if cfg.TorEnabled {
		torDialer := &tor.DefaultDialer{}
		socks5Config.Dial = torDialer.Dial
		httpConfig.Dial = torDialer.Dial
		logger.Info().Msg("Tor mode enabled")

		torController := tor.NewTorController(torDialer)
		ch := make(chan bool)
		go tor.SwitcherIdentity(&logger, torController, cfg.TorIdentityInterval, ch)

		go func() {
			<-ch
			logger.Fatal().Msg("Tor identity switcher stopped")
		}()
	}

	if len(cfg.Credentials) > 0 {
		authenticator := &socks5.UserPassAuthenticator{
			Credentials: credentials,
		}
		socks5Config.Authentication = append(socks5Config.Authentication, authenticator)
	}

	sock5Server := socks5.New(&socks5Config)

	go func() {
		logger.Info().Msgf("Starting HTTP proxy server on %s://%s", cfg.Network, cfg.ADDRHttp)

		server := &http.Server{
			Addr:         cfg.ADDRHttp,
			Handler:      httpServer,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		}

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Msg(err.Error())
		}
	}()

	go func() {
		logger.Info().Msgf("Starting SOCKS5 server on %s://%s", cfg.Network, cfg.ADDR)
		if err := sock5Server.ListenAndServe(cfg.Network, cfg.ADDR); err != nil {
			logger.Fatal().Msg(err.Error())
		}
	}()

	select {}
}
