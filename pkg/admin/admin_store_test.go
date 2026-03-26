package admin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestBoltAdminStore_SaveAndLoad(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "admin.db")
	store := NewBoltAdminStore(dbPath)

	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	require.NoError(t, err)

	// Initially, no admin should exist
	username, passwordHash, found, err := store.Load()
	assert.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, "", username)
	assert.Equal(t, "", passwordHash)

	// Save admin credentials
	err = store.Save("admin", string(hash))
	assert.NoError(t, err)

	// Load should now return the saved credentials
	username, passwordHash, found, err = store.Load()
	assert.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "admin", username)
	assert.Equal(t, string(hash), passwordHash)
}

func TestBoltAdminStore_SaveOverwrites(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "admin.db")
	store := NewBoltAdminStore(dbPath)

	hash1, err := bcrypt.GenerateFromPassword([]byte("secret1"), bcrypt.DefaultCost)
	require.NoError(t, err)
	hash2, err := bcrypt.GenerateFromPassword([]byte("secret2"), bcrypt.DefaultCost)
	require.NoError(t, err)

	// Save first admin
	err = store.Save("admin", string(hash1))
	assert.NoError(t, err)

	// Save second admin (should overwrite)
	err = store.Save("newadmin", string(hash2))
	assert.NoError(t, err)

	// Load should return the new admin
	username, passwordHash, found, err := store.Load()
	assert.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "newadmin", username)
	assert.Equal(t, string(hash2), passwordHash)
	assert.NotEqual(t, string(hash1), passwordHash)
}

func TestBoltAdminStore_NilStore(t *testing.T) {
	t.Parallel()

	var store *BoltAdminStore

	// Load from nil should return empty
	username, passwordHash, found, err := store.Load()
	assert.NoError(t, err)
	assert.False(t, found)
	assert.Equal(t, "", username)
	assert.Equal(t, "", passwordHash)

	// Save to nil should not error
	err = store.Save("admin", "hash")
	assert.NoError(t, err)
}

func TestBoltAdminStore_EmptyPath(t *testing.T) {
	t.Parallel()

	store := NewBoltAdminStore("")

	// Load from empty path should return empty
	_, _, found, err := store.Load()
	assert.NoError(t, err)
	assert.False(t, found)

	// Save to empty path should not error
	err = store.Save("admin", "hash")
	assert.NoError(t, err)
}

func TestBoltAdminStore_PartialCredentials(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "admin.db")
	store := NewBoltAdminStore(dbPath)

	// Save with empty password hash
	err := store.Save("admin", "")
	assert.NoError(t, err)

	// Should not be found (both username and hash must exist)
	_, _, found, err := store.Load()
	assert.NoError(t, err)
	assert.False(t, found)
}

func TestBoltAdminStore_SaveFailsIfDirMissing(t *testing.T) {
	t.Parallel()

	dbDir := filepath.Join(t.TempDir(), "subdir", "nested")
	dbPath := filepath.Join(dbDir, "admin.db")
	store := NewBoltAdminStore(dbPath)

	// Directory should not exist yet
	_, err := os.Stat(dbDir)
	assert.True(t, os.IsNotExist(err))

	// Save should fail when directory is not pre-created.
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	err = store.Save("admin", string(hash))
	assert.Error(t, err)
}

func TestBoltAdminStore_PersistsAcrossInstances(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "admin.db")

	hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	require.NoError(t, err)

	// First instance: save credentials
	store1 := NewBoltAdminStore(dbPath)
	err = store1.Save("admin", string(hash))
	assert.NoError(t, err)

	// Second instance: load credentials
	store2 := NewBoltAdminStore(dbPath)
	username, passwordHash, found, err := store2.Load()
	assert.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "admin", username)
	assert.Equal(t, string(hash), passwordHash)
}

func TestBoltAdminStore_InvalidDatabaseFile(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "not_a_db.txt")

	// Create a non-database file
	err := os.WriteFile(dbPath, []byte("not a valid boltdb"), 0o644)
	require.NoError(t, err)

	store := NewBoltAdminStore(dbPath)

	// Loading from invalid DB should error
	_, _, _, err = store.Load()
	assert.Error(t, err)

	// Saving should also error (can't overwrite with valid DB)
	err = store.Save("admin", "hash")
	assert.Error(t, err)
}

func TestBoltAdminStore_PermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("skipping permission test when running as root")
	}

	t.Parallel()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "admin.db")

	// Create DB first
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	store := NewBoltAdminStore(dbPath)
	err := store.Save("admin", string(hash))
	require.NoError(t, err)

	// Remove read permission from directory
	err = os.Chmod(tmpDir, 0o000)
	require.NoError(t, err)
	defer os.Chmod(tmpDir, 0o755)

	// Load should fail due to permission error
	_, _, _, err = store.Load()
	assert.Error(t, err)
}
