package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/caarlos0/env/v10"
	"github.com/rs/zerolog"
	"github.com/ryanbekhen/nanoproxy/pkg/admin"
	"github.com/ryanbekhen/nanoproxy/pkg/config"
	"github.com/ryanbekhen/nanoproxy/pkg/credential"
	"github.com/ryanbekhen/nanoproxy/pkg/httpproxy"
	"github.com/ryanbekhen/nanoproxy/pkg/resolver"
	"github.com/ryanbekhen/nanoproxy/pkg/socks5"
	"github.com/ryanbekhen/nanoproxy/pkg/tor"
	"github.com/ryanbekhen/nanoproxy/pkg/userstore"
	"net"
	"net/http"

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

	// Create users directory if it doesn't exist
	usersDir := filepath.Dir(cfg.UsersFile)
	if err := os.MkdirAll(usersDir, 0755); err != nil {
		logger.Warn().Err(err).Msg("Failed to create users directory")
	}

	// Initialize user store
	userStore, err := userstore.NewStore(cfg.UsersFile)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to initialize user store")
	}

	// Initialize credentials from both environment and user store
	var credentials credential.Store
	var adminCredentials credential.Store
	
	// If credentials are provided via environment, use StaticCredentialStore for both proxy and admin
	if len(cfg.Credentials) > 0 {
		staticStore := credential.NewStaticCredentialStore()
		for _, cred := range cfg.Credentials {
			credArr := strings.Split(cred, ":")
			if len(credArr) != 2 {
				logger.Fatal().Msgf("Invalid credential: %s", cred)
			}
			staticStore.Add(credArr[0], credArr[1])
		}
		credentials = staticStore
		adminCredentials = staticStore
	} else {
		// Use user store for proxy authentication
		credentials = userStore
		// Only use credentials for admin if there are users in the store
		if userStore.Count() > 0 {
			adminCredentials = userStore
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

	if credentials != nil {
		authenticator := &socks5.UserPassAuthenticator{
			Credentials: credentials,
		}
		socks5Config.Authentication = append(socks5Config.Authentication, authenticator)
	}

	sock5Server := socks5.New(&socks5Config)

	// Start admin panel if enabled
	if cfg.AdminEnabled {
		adminConfig := &admin.Config{
			UserStore:   userStore,
			Credentials: adminCredentials,
			Logger:      &logger,
		}
		adminHandler := admin.New(adminConfig)

		go func() {
			logger.Info().Msgf("Starting admin panel on %s://%s", cfg.Network, cfg.ADDRAdmin)

			server := &http.Server{
				Addr:         cfg.ADDRAdmin,
				Handler:      adminHandler,
				ReadTimeout:  15 * time.Second,
				WriteTimeout: 15 * time.Second,
				IdleTimeout:  60 * time.Second,
			}

			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Fatal().Msg(err.Error())
			}
		}()
	}

	go func() {
		logger.Info().Msgf("Starting HTTP proxy server on %s://%s", cfg.Network, cfg.ADDRHttp)

		server := &http.Server{
			Addr:         cfg.ADDRHttp,
			Handler:      httpServer,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		}

		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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
