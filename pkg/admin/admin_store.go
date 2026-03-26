package admin

import (
	"errors"
	"os"

	"go.etcd.io/bbolt"
)

var adminBucket = []byte("admin")

// AdminCredentialStore persists the admin login account used by the admin console.
type AdminCredentialStore interface {
	Load() (username string, passwordHash string, found bool, err error)
	Save(username string, passwordHash string) error
}

type BoltAdminStore struct {
	path string
}

func NewBoltAdminStore(path string) *BoltAdminStore {
	return &BoltAdminStore{path: path}
}

func (b *BoltAdminStore) Load() (string, string, bool, error) {
	if b == nil || b.path == "" {
		return "", "", false, nil
	}

	if _, err := os.Stat(b.path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", "", false, nil
		}
		return "", "", false, err
	}

	db, err := bbolt.Open(b.path, 0o600, nil)
	if err != nil {
		return "", "", false, err
	}
	defer db.Close()

	var username, passwordHash string
	err = db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(adminBucket)
		if bucket == nil {
			return nil
		}

		username = string(bucket.Get([]byte("username")))
		passwordHash = string(bucket.Get([]byte("password_hash")))
		return nil
	})
	if err != nil {
		return "", "", false, err
	}

	if username == "" || passwordHash == "" {
		return "", "", false, nil
	}

	return username, passwordHash, true, nil
}

func (b *BoltAdminStore) Save(username string, passwordHash string) error {
	if b == nil || b.path == "" {
		return nil
	}

	db, err := bbolt.Open(b.path, 0o600, nil)
	if err != nil {
		return err
	}
	defer db.Close()

	return db.Update(func(tx *bbolt.Tx) error {
		_ = tx.DeleteBucket(adminBucket)

		bucket, err := tx.CreateBucket(adminBucket)
		if err != nil {
			return err
		}

		if err := bucket.Put([]byte("username"), []byte(username)); err != nil {
			return err
		}
		if err := bucket.Put([]byte("password_hash"), []byte(passwordHash)); err != nil {
			return err
		}
		return nil
	})
}
