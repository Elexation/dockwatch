// Package store persists the hub's check results and agent poll status in a
// disposable bbolt file, rebuilt from scratch if lost.
package store

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

const dbFile = "dockwatch.db"

// bbolt's default lock wait is forever; bound it so a second opener can't hang.
const openTimeout = 3 * time.Second

const (
	dbPerm  os.FileMode = 0o600
	dirPerm os.FileMode = 0o700
)

var (
	bucketChecks   = []byte("checks")
	bucketAgents   = []byte("agents")
	bucketNotified = []byte("notified")
	bucketAuth     = []byte("auth")
	bucketSessions = []byte("sessions")
)

type Store struct {
	db *bolt.DB
}

// Open creates dir/dockwatch.db if needed; the caller must Close it.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, fmt.Errorf("create data dir %s: %w", dir, err)
	}
	path := filepath.Join(dir, dbFile)
	db, err := bolt.Open(path, dbPerm, &bolt.Options{Timeout: openTimeout})
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketChecks, bucketAgents, bucketNotified, bucketAuth, bucketSessions} {
			if _, berr := tx.CreateBucketIfNotExists(b); berr != nil {
				return berr
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("init buckets in %s: %w", path, err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}
