package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
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
	"github.com/ryanbekhen/nanoproxy/pkg/traffic"

	_ "time/tzdata"
)

func main() {
	cfg := &config.Config{}
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).With().Timestamp().Logger()

	if err := env.Parse(cfg); err != nil {
		logger.Fatal().Msg(err.Error())
	}

	level, err := zerolog.ParseLevel(strings.ToLower(strings.TrimSpace(cfg.LogLevel)))
	if err != nil {
		logger.Warn().Str("log_level", cfg.LogLevel).Msg("Invalid LOG_LEVEL, falling back to info")
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)
	logger = logger.Level(level)

	loc, _ := time.LoadLocation(cfg.Timezone)
	if loc != nil {
		time.Local = loc
	}

	credentials, userFileStore, err := buildCredentialStore(cfg)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to initialize credentials")
	}
	adminStore := admin.NewBoltAdminStore(cfg.UserStorePath)

	dnsResolver := &resolver.DNSResolver{}
	trafficTracker := traffic.NewTracker()

	// Load persisted traffic totals
	trafficStore := traffic.NewBoltStore(cfg.UserStorePath)
	if err := trafficTracker.LoadPersistedTotals(trafficStore); err != nil {
		logger.Warn().Err(err).Msg("Failed to load persisted traffic totals")
	}

	httpConfig := httpproxy.Config{
		Credentials:       credentials,
		Logger:            &logger,
		DestConnTimeout:   cfg.DestTimeout,
		ClientConnTimeout: cfg.ClientTimeout,
		Dial:              net.Dial,
		Resolver:          dnsResolver,
		Tracker:           trafficTracker,
	}

	httpServer := httpproxy.New(&httpConfig)

	socks5Config := socks5.Config{
		Logger:            &logger,
		DestConnTimeout:   cfg.DestTimeout,
		ClientConnTimeout: cfg.ClientTimeout,
		Resolver:          dnsResolver,
		Tracker:           trafficTracker,
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

	socks5Server := socks5.New(&socks5Config)

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
		if err := socks5Server.ListenAndServe(cfg.Network, cfg.ADDR); err != nil {
			logger.Fatal().Msg(err.Error())
		}
	}()

	adminServer := admin.New(&admin.Config{
		Credentials:      credentials,
		UserStore:        userFileStore,
		AdminStore:       adminStore,
		TrafficStore:     trafficStore,
		Tracker:          trafficTracker,
		CookieSecure:     cfg.AdminCookieSecure,
		MaxLoginAttempts: cfg.AdminMaxLoginAttempts,
		LoginWindow:      cfg.AdminLoginWindow,
		LockoutDuration:  cfg.AdminLockoutDuration,
		AllowedOrigins:   cfg.AdminAllowedOrigins,
		Logger:           &logger,
	})

	go func() {
		logger.Info().Msgf("Starting admin server on %s", cfg.ADDRAdmin)

		server := &http.Server{
			Addr:         cfg.ADDRAdmin,
			Handler:      adminServer.Handler(),
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		}

		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal().Msg(err.Error())
		}
	}()

	select {}
}

func buildCredentialStore(cfg *config.Config) (*credential.StaticCredentialStore, credential.PersistentStore, error) {
	userStore := credential.NewBoltStore(cfg.UserStorePath)

	credentials := credential.NewStaticCredentialStore()
	if err := credential.LoadInto(userStore, credentials); err != nil {
		return nil, userStore, fmt.Errorf("load persisted proxy users: %w", err)
	}

	return credentials, userStore, nil
}
