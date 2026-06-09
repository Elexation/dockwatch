package store

import (
	"encoding/json"
	"time"

	bolt "go.etcd.io/bbolt"
)

// NotifiedState records, per image reference, the last update the operator was
// told about, so a notification fires only when the discovered latest differs.
type NotifiedState struct {
	Ref        string    `json:"ref"`
	Version    string    `json:"version,omitempty"` // last notified newest tag (SEMVER)
	Digest     string    `json:"digest,omitempty"`  // last notified registry digest (mutable tag / republish)
	NotifiedAt time.Time `json:"notified_at"`
}

func (s *Store) PutNotified(n NotifiedState) error {
	data, err := json.Marshal(n)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketNotified).Put([]byte(n.Ref), data)
	})
}

// GetNotified returns the stored state for ref, with found=false if none exists.
func (s *Store) GetNotified(ref string) (NotifiedState, bool, error) {
	var n NotifiedState
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketNotified).Get([]byte(ref))
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &n)
	})
	return n, found, err
}
