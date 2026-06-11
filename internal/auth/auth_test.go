package auth

import (
	"strings"
	"testing"
)

func TestHashVerifyRoundTrip(t *testing.T) {
	const pw = "correct horse battery staple"
	h, err := Hash(pw)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=4$") {
		t.Errorf("unexpected encoding prefix: %s", h)
	}
	if ok, err := Verify(h, pw); err != nil || !ok {
		t.Errorf("Verify correct: ok=%v err=%v", ok, err)
	}
	if ok, err := Verify(h, "wrong password"); err != nil || ok {
		t.Errorf("Verify wrong: ok=%v err=%v", ok, err)
	}
}

func TestHashUniqueSalt(t *testing.T) {
	a, _ := Hash("same")
	b, _ := Hash("same")
	if a == b {
		t.Error("two hashes of the same password are identical (salt not random)")
	}
}

func TestVerifyMalformed(t *testing.T) {
	for _, s := range []string{
		"",
		"not-a-hash",
		"$argon2id$v=19$m=65536,t=3,p=4$onlysalt",
		"$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
		"$argon2id$v=18$m=65536,t=3,p=4$c2FsdA$aGFzaA",
	} {
		if ok, err := Verify(s, "x"); ok || err == nil {
			t.Errorf("Verify(%q): ok=%v err=%v, want ok=false err!=nil", s, ok, err)
		}
	}
}

func TestNewSessionID(t *testing.T) {
	a, err := NewSessionID()
	if err != nil {
		t.Fatalf("NewSessionID: %v", err)
	}
	b, _ := NewSessionID()
	if a == b {
		t.Error("session ids collided")
	}
	if len(a) != 43 { // 32 random bytes -> 43 base64url chars, unpadded
		t.Errorf("session id length = %d, want 43", len(a))
	}
}
