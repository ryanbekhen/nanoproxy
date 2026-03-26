package credential

import (
	"errors"
	"os"
	"path/filepath"

	"go.etcd.io/bbolt"
)

var usersBucket = []byte("users")

type BoltStore struct {
	path string
}

func NewBoltStore(path string) *BoltStore {
	return &BoltStore{path: path}
}

func (b *BoltStore) Path() string {
	if b == nil {
		return ""
	}

	return b.path
}

func (b *BoltStore) Load() (map[string]string, error) {
	if b == nil || b.path == "" {
		return map[string]string{}, nil
	}

	if _, err := os.Stat(b.path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]string{}, nil
		}
		return nil, err
	}

	db, err := bbolt.Open(b.path, 0o600, nil)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	snapshot := map[string]string{}
	err = db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(usersBucket)
		if bucket == nil {
			return nil
		}

		return bucket.ForEach(func(k, v []byte) error {
			snapshot[string(k)] = string(v)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	return snapshot, nil
}

func (b *BoltStore) Save(snapshot map[string]string) error {
	if b == nil || b.path == "" {
		return nil
	}

	dir := filepath.Dir(b.path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
	}

	db, err := bbolt.Open(b.path, 0o600, nil)
	if err != nil {
		return err
	}
	defer db.Close()

	return db.Update(func(tx *bbolt.Tx) error {
		_ = tx.DeleteBucket(usersBucket)

		bucket, err := tx.CreateBucket(usersBucket)
		if err != nil {
			return err
		}

		for username, passwordHash := range snapshot {
			if err := bucket.Put([]byte(username), []byte(passwordHash)); err != nil {
				return err
			}
		}

		return nil
	})
}
