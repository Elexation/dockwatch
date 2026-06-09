package store

import (
	"encoding/json"
	"time"

	bolt "go.etcd.io/bbolt"
)

// AgentStatus is one agent's last poll outcome; DownNotified gates the down-alert to once per transition.
type AgentStatus struct {
	Name                string    `json:"name"`
	LastOK              bool      `json:"last_ok"`
	LastPoll            time.Time `json:"last_poll"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	DownNotified        bool      `json:"down_notified"`
}

func (s *Store) PutAgent(a AgentStatus) error {
	data, err := json.Marshal(a)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAgents).Put([]byte(a.Name), data)
	})
}

// GetAgent returns the stored status for name, with found=false if none exists.
func (s *Store) GetAgent(name string) (AgentStatus, bool, error) {
	var a AgentStatus
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketAgents).Get([]byte(name))
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &a)
	})
	return a, found, err
}

func (s *Store) AllAgents() ([]AgentStatus, error) {
	var out []AgentStatus
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketAgents).ForEach(func(_, v []byte) error {
			var a AgentStatus
			if err := json.Unmarshal(v, &a); err != nil {
				return err
			}
			out = append(out, a)
			return nil
		})
	})
	return out, err
}
