package config

import (
	"testing"

	"github.com/caarlos0/env/v10"
)

func TestConfig_DefaultNoAuthMode(t *testing.T) {
	t.Parallel()

	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}

	if cfg.NoAuthMode {
		t.Fatal("expected NO_AUTH_MODE default to false")
	}
}

func TestConfig_ParseNoAuthModeFromEnv(t *testing.T) {
	t.Setenv("NO_AUTH_MODE", "true")

	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}

	if !cfg.NoAuthMode {
		t.Fatal("expected NO_AUTH_MODE=true from environment")
	}
}
