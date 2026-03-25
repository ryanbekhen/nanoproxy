package main

import (
	"path/filepath"
	"testing"

	"github.com/ryanbekhen/nanoproxy/pkg/config"
	"github.com/ryanbekhen/nanoproxy/pkg/credential"
)

func TestBuildCredentialStore_MergesFileAndEnv_EnvOverrides(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "data.db")
	userStore := credential.NewBoltStore(storePath)

	persisted := credential.NewStaticCredentialStore()
	persisted.Add("shared-user", "file-password")
	persisted.Add("file-only-user", "file-only-password")
	if err := userStore.Save(persisted.Snapshot()); err != nil {
		t.Fatalf("save persisted users: %v", err)
	}

	cfg := &config.Config{
		AdminUsername: "admin",
		AdminPassword: "admin-secret",
		UserStorePath: storePath,
		Credentials: []string{
			"shared-user:" + hashedPassword(t, "env-password"),
			"env-only-user:" + hashedPassword(t, "env-only-password"),
		},
	}

	credentials, _, err := buildCredentialStore(cfg)
	if err != nil {
		t.Fatalf("buildCredentialStore returned error: %v", err)
	}
	if credentials == nil {
		t.Fatal("expected non-nil credentials")
	}

	if !credentials.Valid("file-only-user", "file-only-password") {
		t.Fatal("expected file-only user to remain valid")
	}
	if !credentials.Valid("env-only-user", "env-only-password") {
		t.Fatal("expected env-only user to be valid")
	}
	if !credentials.Valid("shared-user", "env-password") {
		t.Fatal("expected shared user to use env password")
	}
	if credentials.Valid("shared-user", "file-password") {
		t.Fatal("expected file password to be overridden for shared user")
	}
}

func TestBuildCredentialStore_NoAdminAndNoEnvCredentials_ReturnsNilStore(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{}

	credentials, userStore, err := buildCredentialStore(cfg)
	if err != nil {
		t.Fatalf("buildCredentialStore returned error: %v", err)
	}
	if credentials != nil {
		t.Fatal("expected nil credentials when no admin and no env credentials")
	}
	if userStore == nil {
		t.Fatal("expected non-nil persistent store")
	}
}

func TestBuildCredentialStore_InvalidCredentialFormat_ReturnsError(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{
		Credentials: []string{"invalid-format"},
	}

	credentials, _, err := buildCredentialStore(cfg)
	if err == nil {
		t.Fatal("expected error for invalid credential format")
	}
	if credentials != nil {
		t.Fatal("expected nil credentials on error")
	}
}

func hashedPassword(t *testing.T, raw string) string {
	t.Helper()

	store := credential.NewStaticCredentialStore()
	store.Add("tmp", raw)

	hash, ok := store.GetHashed("tmp")
	if !ok {
		t.Fatal("failed to generate bcrypt hash")
	}

	return hash
}
