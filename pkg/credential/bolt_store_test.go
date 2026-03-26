package credential

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBoltStore_SaveAndLoad(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "data.db")
	store := NewBoltStore(path)

	snapshot := map[string]string{
		"alice": "$2a$10$JGKWBfX0VTqflV6kNfSLweBzA6YxQ8fFiQvCg2Vf1uNhM6o6z8brS",
		"bob":   "$2a$10$wRPS8Qnmfjzb2n4h2ZVqKegc7MypvJ.p3nQoIc0K2fWzEo.5hF7R2",
	}

	require.NoError(t, store.Save(snapshot))

	restored, err := store.Load()
	require.NoError(t, err)
	assert.Equal(t, snapshot, restored)
}

func TestBoltStore_Load_FileNotExist(t *testing.T) {
	t.Parallel()

	store := NewBoltStore(filepath.Join(t.TempDir(), "missing.db"))
	restored, err := store.Load()
	require.NoError(t, err)
	assert.Empty(t, restored)
}
