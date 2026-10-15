package store

import (
	"encoding/json"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Session maps a random id to a username with a sliding expiry.
type Session struct {
	ID       string    `json:"id"`
	Username string    `json:"username"`
	Expiry   time.Time `json:"expiry"`
	Epoch    uint64    `json:"epoch"` // admin Epoch it was minted under
}

// PutSession stores (or replaces) a session.
func (s *Store) PutSession(sess Session) error {
	data, err := json.Marshal(sess)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSessions).Put([]byte(sess.ID), data)
	})
}

// ExtendSession moves an existing session's expiry to expiry; found=false if it
// is gone, so a refresh racing a logout cannot write it back.
func (s *Store) ExtendSession(id string, expiry time.Time) (bool, error) {
	var found bool
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSessions)
		v := b.Get([]byte(id))
		if v == nil {
			return nil
		}
		var sess Session
		if err := json.Unmarshal(v, &sess); err != nil {
			return err
		}
		sess.Expiry = expiry
		data, err := json.Marshal(sess)
		if err != nil {
			return err
		}
		found = true
		return b.Put([]byte(id), data)
	})
	return found, err
}

// GetSession returns the session for id (found=false if none); expiry is the caller's to check.
func (s *Store) GetSession(id string) (Session, bool, error) {
	var sess Session
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketSessions).Get([]byte(id))
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &sess)
	})
	return sess, found, err
}

// DeleteSession removes one session (logout or expired-id eviction).
func (s *Store) DeleteSession(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSessions).Delete([]byte(id))
	})
}

// ClearSessions removes every session, so DW_RESET_ADMIN leaves none live.
func (s *Store) ClearSessions() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket(bucketSessions); err != nil {
			return err
		}
		_, err := tx.CreateBucket(bucketSessions)
		return err
	})
}
