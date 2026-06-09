package store

import (
	"encoding/json"
	"time"

	bolt "go.etcd.io/bbolt"
)

// CheckStatus is the outcome of one image reference's registry check.
type CheckStatus string

const (
	StatusOK           CheckStatus = "ok"            // checked; result fields are current
	StatusAuthRequired CheckStatus = "auth-required" // registry demands auth (anonymous-only)
	StatusRateLimited  CheckStatus = "rate-limited"  // registry returned 429
	StatusError        CheckStatus = "error"         // other failure; Err has detail
)

// CheckResult is a per-reference (not per-container) registry check; hosts sharing an image share one entry and one registry call.
type CheckResult struct {
	Ref            string      `json:"ref"`                       // full reference, e.g. gitea/gitea:1.24.3
	Kind           string      `json:"kind"`                      // LOCAL | SEMVER | DIGEST
	Current        string      `json:"current,omitempty"`         // SEMVER: the running tag's version
	Latest         string      `json:"latest,omitempty"`          // SEMVER: newest same-scheme tag, when newer
	UpdateKind     string      `json:"update_kind,omitempty"`     // major | minor | patch, when computable
	RegistryDigest string      `json:"registry_digest,omitempty"` // registry index digest of the tag
	Status         CheckStatus `json:"status"`
	CheckedAt      time.Time   `json:"checked_at"`
	Err            string      `json:"err,omitempty"`
}

func (s *Store) PutCheck(r CheckResult) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketChecks).Put([]byte(r.Ref), data)
	})
}

// GetCheck returns the stored result for ref, with found=false if none exists.
func (s *Store) GetCheck(ref string) (CheckResult, bool, error) {
	var r CheckResult
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketChecks).Get([]byte(ref))
		if v == nil {
			return nil
		}
		found = true
		return json.Unmarshal(v, &r)
	})
	return r, found, err
}

func (s *Store) AllChecks() ([]CheckResult, error) {
	var out []CheckResult
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketChecks).ForEach(func(_, v []byte) error {
			var r CheckResult
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			out = append(out, r)
			return nil
		})
	})
	return out, err
}
