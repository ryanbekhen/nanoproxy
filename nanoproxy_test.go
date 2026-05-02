package main

import (
	"path/filepath"
	"testing"

	"github.com/ryanbekhen/nanoproxy/pkg/config"
	"github.com/ryanbekhen/nanoproxy/pkg/credential"
)

func TestBuildCredentialStore_LoadsFromDatabase(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "data.db")
	userStore := credential.NewBoltStore(storePath)

	persisted := credential.NewStaticCredentialStore()
	persisted.Add("db-user", "password")
	if err := userStore.Save(persisted.Snapshot()); err != nil {
		t.Fatalf("save persisted users: %v", err)
	}

	cfg := &config.Config{
		UserStorePath: storePath,
	}

	credentials, _, err := buildCredentialStore(cfg)
	if err != nil {
		t.Fatalf("buildCredentialStore returned error: %v", err)
	}
	if credentials == nil {
		t.Fatal("expected non-nil credentials")
	}

	if !credentials.Valid("db-user", "password") {
		t.Fatal("expected db-user to be valid from database")
	}
}

func TestProxyCredentialsForMode_NoAuthEnabled(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{NoAuthMode: true}
	credentials := credential.NewStaticCredentialStore()
	credentials.Add("db-user", "password")

	selected := proxyCredentialsForMode(cfg, credentials)
	if selected != nil {
		t.Fatal("expected nil credentials in NO_AUTH_MODE")
	}
}

func TestProxyCredentialsForMode_NoAuthDisabled(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{NoAuthMode: false}
	credentials := credential.NewStaticCredentialStore()
	credentials.Add("db-user", "password")

	selected := proxyCredentialsForMode(cfg, credentials)
	if selected == nil {
		t.Fatal("expected non-nil credentials when NO_AUTH_MODE is disabled")
	}
}

func TestAdminEnabledForMode_NoAuthEnabled(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{NoAuthMode: true}
	if adminEnabledForMode(cfg) {
		t.Fatal("expected admin to be disabled when NO_AUTH_MODE is enabled")
	}
}

func TestAdminEnabledForMode_NoAuthDisabled(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{NoAuthMode: false}
	if !adminEnabledForMode(cfg) {
		t.Fatal("expected admin to be enabled when NO_AUTH_MODE is disabled")
	}
}
