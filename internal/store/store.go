// Package store persists the hub's state in a single bbolt file. Most of it is
// cache that rebuilds itself: check results, agent poll status, and what the
// operator has already been notified about. The auth and sessions buckets are
// not. Deleting the file also destroys the admin record, which re-arms the
// unauthenticated first-run setup page; DW_RESET_ADMIN is the intended way to
// reset the admin account.
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
	bucketMeta     = []byte("meta")
)

// Store is an open handle on the hub's bbolt database.
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
		for _, b := range [][]byte{bucketChecks, bucketAgents, bucketNotified, bucketAuth, bucketSessions, bucketMeta} {
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

// Close releases the database file lock.
func (s *Store) Close() error {
	return s.db.Close()
}

// pruneKeys deletes every key in bucket that keep rejects and returns how many
// it removed. Keys are collected first, since bbolt cursors cannot delete safely.
func (s *Store) pruneKeys(bucket []byte, keep func(key string) bool) (int, error) {
	var drop [][]byte
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucket)
		if err := b.ForEach(func(k, _ []byte) error {
			if !keep(string(k)) {
				drop = append(drop, append([]byte(nil), k...))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, k := range drop {
			if err := b.Delete(k); err != nil {
				return err
			}
		}
		return nil
	})
	return len(drop), err
}
