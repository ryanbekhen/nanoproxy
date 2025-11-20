package userstore

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewStore(t *testing.T) {
	tmpFile := "/tmp/test_users.json"
	defer os.Remove(tmpFile)

	store, err := NewStore(tmpFile)
	require.NoError(t, err)
	assert.NotNil(t, store)
	assert.Equal(t, 0, store.Count())
}

func TestStore_Add(t *testing.T) {
	tmpFile := "/tmp/test_users_add.json"
	defer os.Remove(tmpFile)

	store, err := NewStore(tmpFile)
	require.NoError(t, err)

	err = store.AddUser("testuser", "testpass")
	require.NoError(t, err)

	assert.Equal(t, 1, store.Count())
	assert.True(t, store.Valid("testuser", "testpass"))
	assert.False(t, store.Valid("testuser", "wrongpass"))
}

func TestStore_AddWithHash(t *testing.T) {
	tmpFile := "/tmp/test_users_add_hash.json"
	defer os.Remove(tmpFile)

	store, err := NewStore(tmpFile)
	require.NoError(t, err)

	// Pre-hashed password for "testpass"
	hash := "$2a$10$rVwBqGdTI.kHqBCZqg1qxOX5s.9LWj0/ZqQP3nYLCPGSbQZzZ9Z0O"
	err = store.AddWithHash("testuser", hash)
	require.NoError(t, err)

	assert.Equal(t, 1, store.Count())
}

func TestStore_Delete(t *testing.T) {
	tmpFile := "/tmp/test_users_delete.json"
	defer os.Remove(tmpFile)

	store, err := NewStore(tmpFile)
	require.NoError(t, err)

	err = store.AddUser("testuser", "testpass")
	require.NoError(t, err)
	assert.Equal(t, 1, store.Count())

	err = store.Delete("testuser")
	require.NoError(t, err)
	assert.Equal(t, 0, store.Count())
	assert.False(t, store.Valid("testuser", "testpass"))
}

func TestStore_List(t *testing.T) {
	tmpFile := "/tmp/test_users_list.json"
	defer os.Remove(tmpFile)

	store, err := NewStore(tmpFile)
	require.NoError(t, err)

	err = store.AddUser("user1", "pass1")
	require.NoError(t, err)
	err = store.AddUser("user2", "pass2")
	require.NoError(t, err)

	users := store.List()
	assert.Equal(t, 2, len(users))
	assert.Contains(t, users, "user1")
	assert.Contains(t, users, "user2")
}

func TestStore_Get(t *testing.T) {
	tmpFile := "/tmp/test_users_get.json"
	defer os.Remove(tmpFile)

	store, err := NewStore(tmpFile)
	require.NoError(t, err)

	err = store.AddUser("testuser", "testpass")
	require.NoError(t, err)

	user, ok := store.Get("testuser")
	assert.True(t, ok)
	assert.Equal(t, "testuser", user.Username)

	user, ok = store.Get("nonexistent")
	assert.False(t, ok)
	assert.Nil(t, user)
}

func TestStore_Persistence(t *testing.T) {
	tmpFile := "/tmp/test_users_persist.json"
	defer os.Remove(tmpFile)

	// Create store and add users
	store1, err := NewStore(tmpFile)
	require.NoError(t, err)

	err = store1.AddUser("user1", "pass1")
	require.NoError(t, err)
	err = store1.AddUser("user2", "pass2")
	require.NoError(t, err)

	// Create a new store instance and verify persistence
	store2, err := NewStore(tmpFile)
	require.NoError(t, err)

	assert.Equal(t, 2, store2.Count())
	assert.True(t, store2.Valid("user1", "pass1"))
	assert.True(t, store2.Valid("user2", "pass2"))
}
