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
