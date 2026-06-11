// Package auth provides argon2id password hashing (PHC string form) and random
// session identifiers. It is stateless; persistence lives in internal/store.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Params are the argon2id cost parameters, encoded into each hash so they can
// be raised later without invalidating stored passwords.
type Params struct {
	Memory  uint32 // KiB
	Time    uint32 // iterations
	Threads uint8
	SaltLen uint32 // bytes
	KeyLen  uint32 // bytes
}

// DefaultParams is RFC 9106's second recommended (memory-constrained) option,
// tuned for roughly 100ms on a Raspberry Pi 4.
var DefaultParams = Params{
	Memory:  64 * 1024,
	Time:    3,
	Threads: 4,
	SaltLen: 16,
	KeyLen:  32,
}

// ErrMalformedHash reports an unparseable encoded hash; a plain mismatch is
// ok=false with a nil error instead.
var ErrMalformedHash = errors.New("auth: malformed argon2id hash")

// Hash returns an argon2id PHC encoding of password with a fresh random salt.
func Hash(password string) (string, error) {
	return hashWith(password, DefaultParams)
}

func hashWith(password string, p Params) (string, error) {
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// Verify reports whether password matches the PHC-encoded hash. A mismatch is
// (false, nil); only an unparseable encoding returns an error.
func Verify(encoded, password string) (bool, error) {
	p, salt, want, err := decode(encoded)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// decode parses a PHC string into its params, salt, and stored key.
func decode(encoded string) (Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return Params{}, nil, nil, ErrMalformedHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return Params{}, nil, nil, ErrMalformedHash
	}
	var p Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); err != nil {
		return Params{}, nil, nil, ErrMalformedHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Params{}, nil, nil, ErrMalformedHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Params{}, nil, nil, ErrMalformedHash
	}
	return p, salt, want, nil
}

// NewSessionID returns a random 256-bit session id as unpadded URL-safe base64.
func NewSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
