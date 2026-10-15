package store

import (
	"encoding/json"
	"errors"
	"time"

	bolt "go.etcd.io/bbolt"
)

// adminKey is the fixed key for the single admin record.
var adminKey = []byte("admin")

var (
	// ErrAdminExists means CreateAdmin found an admin record already in place.
	ErrAdminExists = errors.New("admin already exists")
	// ErrAdminChanged means the admin record moved past the epoch the caller read.
	ErrAdminChanged = errors.New("admin changed concurrently")
)

// Admin is the single administrator account; Hash is an argon2id PHC string.
type Admin struct {
	Username  string    `json:"username"`
	Hash      string    `json:"hash"`
	CreatedAt time.Time `json:"created_at"`
	Epoch     uint64    `json:"epoch"` // bumped on every password change; older sessions die with it
}

// CreateAdmin stores the first admin record. It returns ErrAdminExists if one is
// already there, so two concurrent setups cannot both succeed. With
// ChangePassword it is the only way to write the admin hash; there is
// deliberately no unconditional put, which could replace the hash without
// bumping Epoch.
func (s *Store) CreateAdmin(a Admin) error {
	data, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAuth)
		if b.Get(adminKey) != nil {
			return ErrAdminExists
		}
		return b.Put(adminKey, data)
	})
}

// ChangePassword swaps in hash and bumps the epoch in one write, but only while
// the stored epoch is still epoch; otherwise it returns ErrAdminChanged. It
// returns the record as written.
func (s *Store) ChangePassword(epoch uint64, hash string) (Admin, error) {
	var a Admin
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAuth)
		v := b.Get(adminKey)
		if v == nil {
			return ErrAdminChanged
		}
		if err := json.Unmarshal(v, &a); err != nil {
			return err
		}
		if a.Epoch != epoch {
			return ErrAdminChanged
		}
		a.Hash = hash
		a.Epoch++
		data, err := json.Marshal(a)
		if err != nil {
			return err
		}
		return b.Put(adminKey, data)
	})
	if err != nil {
		return Admin{}, err
	}
	return a, nil
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
