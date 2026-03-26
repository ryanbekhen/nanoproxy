package traffic

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"go.etcd.io/bbolt"
)

var trafficBucket = []byte("traffic")

type storedTraffic struct {
	UploadBytes   uint64    `json:"upload_bytes"`
	DownloadBytes uint64    `json:"download_bytes"`
	LastClientIP  string    `json:"last_client_ip"`
	LastSeenAt    time.Time `json:"last_seen_at"`
}

type BoltStore struct {
	path string
}

func NewBoltStore(path string) *BoltStore {
	return &BoltStore{path: path}
}

func (b *BoltStore) LoadTraffic() (map[string]UserTotals, error) {
	if b == nil || b.path == "" {
		return map[string]UserTotals{}, nil
	}
	if _, err := os.Stat(b.path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]UserTotals{}, nil
		}
		return nil, err
	}
	db, err := bbolt.Open(b.path, 0o600, nil)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	out := map[string]UserTotals{}
	err = db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(trafficBucket)
		if bucket == nil {
			return nil
		}
		return bucket.ForEach(func(k, v []byte) error {
			var rec storedTraffic
			if err := json.Unmarshal(v, &rec); err != nil {
				return nil
			}
			out[string(k)] = UserTotals{
				UploadBytes:   rec.UploadBytes,
				DownloadBytes: rec.DownloadBytes,
				LastClientIP:  rec.LastClientIP,
				LastSeenAt:    rec.LastSeenAt,
			}
			return nil
		})
	})
	return out, err
}

func (b *BoltStore) SaveTraffic(totals map[string]UserTotals) error {
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
		bucket, err := tx.CreateBucketIfNotExists(trafficBucket)
		if err != nil {
			return err
		}
		for username, t := range totals {
			rec := storedTraffic{
				UploadBytes:   t.UploadBytes,
				DownloadBytes: t.DownloadBytes,
				LastClientIP:  t.LastClientIP,
				LastSeenAt:    t.LastSeenAt,
			}
			data, err := json.Marshal(rec)
			if err != nil {
				continue
			}
			if err := bucket.Put([]byte(username), data); err != nil {
				return err
			}
		}
		return nil
	})
}

func (b *BoltStore) ResetUserTraffic(username string) error {
	if b == nil || b.path == "" {
		return nil
	}
	if _, err := os.Stat(b.path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	db, err := bbolt.Open(b.path, 0o600, nil)
	if err != nil {
		return err
	}
	defer db.Close()

	return db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket(trafficBucket)
		if bucket == nil {
			return nil
		}
		return bucket.Delete([]byte(username))
	})
}
