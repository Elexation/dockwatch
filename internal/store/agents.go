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
	LastPoll            time.Time `json:"last_poll"`             // every poll, successful or not
	LastSuccess         time.Time `json:"last_success,omitzero"` // last poll that actually reached the agent
	ConsecutiveFailures int       `json:"consecutive_failures"`
	DownNotified        bool      `json:"down_notified"`

	LastWireV     int `json:"last_wire_v,omitempty"`     // wire version seen on the last OK poll
	WireNotifiedV int `json:"wire_notified_v,omitempty"` // wire version already alerted on (once-per-detection gate)

	CertNotAfter        time.Time `json:"cert_not_after,omitempty"`        // expiry of the cert served on the last OK poll
	LastRenewalReminder time.Time `json:"last_renewal_reminder,omitempty"` // last staged-bundle alert (renewal push or weekly reminder); non-zero lights the agents-page warn flag
	ReissuePending      bool      `json:"reissue_pending,omitempty"`       // re-issue alert (new address or CA) not yet delivered
}

// UpdateAgent applies fn to name's stored status within one transaction;
// found=false, and fn is not called, if no status exists. It changes only what
// fn touches, but other writers replace whole records, so callers must still
// not overlap them (the scheduler runs the renewal pass and the cycle serially).
func (s *Store) UpdateAgent(name string, fn func(*AgentStatus)) (bool, error) {
	var found bool
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAgents)
		v := b.Get([]byte(name))
		if v == nil {
			return nil
		}
		var a AgentStatus
		if err := json.Unmarshal(v, &a); err != nil {
			return err
		}
		fn(&a)
		data, err := json.Marshal(a)
		if err != nil {
			return err
		}
		found = true
		return b.Put([]byte(name), data)
	})
	return found, err
}

// PutAgent stores a under its name, replacing any previous status.
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

// AllAgents returns every stored agent status, in name order.
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

// PruneAgents drops stored statuses for agents no longer in keep and returns
// the names removed. Status is rebuilt by the next poll, so dropping a
// renamed or decommissioned agent costs nothing and stops it lingering on the
// agents page and in the down-alert evaluation.
func (s *Store) PruneAgents(keep []string) ([]string, error) {
	set := make(map[string]bool, len(keep))
	for _, n := range keep {
		set[n] = true
	}
	var removed []string
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAgents)
		c := b.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			if !set[string(k)] {
				removed = append(removed, string(k))
			}
		}
		for _, n := range removed {
			if err := b.Delete([]byte(n)); err != nil {
				return err
			}
		}
		return nil
	})
	return removed, err
}
