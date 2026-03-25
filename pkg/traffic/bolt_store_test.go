package traffic

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBoltStore_SaveAndLoadTraffic(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "traffic.db")
	store := NewBoltStore(path)

	totals := map[string]UserTotals{
		"alice": {
			UploadBytes:   1024,
			DownloadBytes: 2048,
			LastClientIP:  "10.0.0.2",
			LastSeenAt:    time.Now(),
		},
		"bob": {
			UploadBytes:   512,
			DownloadBytes: 1024,
			LastClientIP:  "10.0.0.3",
			LastSeenAt:    time.Now(),
		},
	}

	require.NoError(t, store.SaveTraffic(totals))

	loaded, err := store.LoadTraffic()
	require.NoError(t, err)
	assert.Len(t, loaded, 2)
	assert.Equal(t, uint64(1024), loaded["alice"].UploadBytes)
	assert.Equal(t, uint64(2048), loaded["alice"].DownloadBytes)
	assert.Equal(t, "10.0.0.2", loaded["alice"].LastClientIP)
}

func TestBoltStore_ResetUserTraffic(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "traffic.db")
	store := NewBoltStore(path)

	totals := map[string]UserTotals{
		"alice": {
			UploadBytes:   1024,
			DownloadBytes: 2048,
			LastClientIP:  "10.0.0.2",
			LastSeenAt:    time.Now(),
		},
	}

	require.NoError(t, store.SaveTraffic(totals))
	require.NoError(t, store.ResetUserTraffic("alice"))

	loaded, err := store.LoadTraffic()
	require.NoError(t, err)
	assert.Empty(t, loaded)
}
