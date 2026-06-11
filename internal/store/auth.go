package store

import (
	"encoding/json"
	"time"

	bolt "go.etcd.io/bbolt"
)

// adminKey is the fixed key for the single admin record.
var adminKey = []byte("admin")

// Admin is the single administrator account; Hash is an argon2id PHC string.
type Admin struct {
	Username  string    `json:"username"`
	Hash      string    `json:"hash"`
	CreatedAt time.Time `json:"created_at"`
}

// PutAdmin stores (or replaces) the admin record.
func (s *Store) PutAdmin(a Admin) error {
	data, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAuth).Put(adminKey, data)
	})
}

// GetAdmin returns the admin record, with found=false if none exists.
func (s *Store) GetAdmin() (Admin, bool, error) {
	var a Admin
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketAuth).Get(adminKey)
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &a)
	})
	return a, found, err
}

// AdminExists reports whether an admin account exists; first-run setup is armed only while it does not.
func (s *Store) AdminExists() (bool, error) {
	var exists bool
	err := s.db.View(func(tx *bolt.Tx) error {
		exists = tx.Bucket(bucketAuth).Get(adminKey) != nil
		return nil
	})
	return exists, err
}

// DeleteAdmin removes the admin record, re-arming first-run setup (DW_RESET_ADMIN).
func (s *Store) DeleteAdmin() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAuth).Delete(adminKey)
	})
}
