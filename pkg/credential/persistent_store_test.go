package credential

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLoadInto_NilStore(t *testing.T) {
	t.Parallel()

	err := LoadInto(nil, nil)
	assert.NoError(t, err)
}

func TestLoadInto_NilPersistentStore(t *testing.T) {
	t.Parallel()

	target := NewStaticCredentialStore()
	err := LoadInto(nil, target)
	assert.NoError(t, err)
}

func TestLoadInto_FromBoltStore(t *testing.T) {
	t.Parallel()

	boltStore := NewBoltStore(t.TempDir() + "/data.db")
	seed := NewStaticCredentialStore()
	seed.Add("alice", "alice-pass")
	seed.Add("bob", "bob-pass")

	assert.NoError(t, boltStore.Save(seed.Snapshot()))

	target := NewStaticCredentialStore()
	err := LoadInto(boltStore, target)
	assert.NoError(t, err)
	assert.True(t, target.Valid("alice", "alice-pass"))
	assert.True(t, target.Valid("bob", "bob-pass"))
}
