package store

import (
	bolt "go.etcd.io/bbolt"
)

var caKeyNotifiedKey = []byte("ca_key_missing_notified")

// CAKeyMissingNotified reports whether the operator has already been alerted
// that minting is blocked on an absent CA key. The alert is a standing
// condition rather than a one-off event, so it needs its own gate to stay
// notify-once across daily renewal passes.
func (s *Store) CAKeyMissingNotified() (bool, error) {
	var v bool
	err := s.db.View(func(tx *bolt.Tx) error {
		v = tx.Bucket(bucketMeta).Get(caKeyNotifiedKey) != nil
		return nil
	})
	return v, err
}

// SetCAKeyMissingNotified records or clears the CA-key-missing alert gate.
func (s *Store) SetCAKeyMissingNotified(notified bool) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketMeta)
		if notified {
			return b.Put(caKeyNotifiedKey, []byte{1})
		}
		return b.Delete(caKeyNotifiedKey)
	})
}
