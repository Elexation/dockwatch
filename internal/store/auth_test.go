package store

import (
	"testing"
	"time"
)

func TestAdminRoundTrip(t *testing.T) {
	s := openTemp(t)
	if exists, err := s.AdminExists(); err != nil || exists {
		t.Fatalf("fresh store AdminExists: exists=%v err=%v, want false", exists, err)
	}
	now := time.Now().Truncate(time.Second)
	want := Admin{Username: "admin", Hash: "$argon2id$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA", CreatedAt: now}
	if err := s.PutAdmin(want); err != nil {
		t.Fatalf("PutAdmin: %v", err)
	}
	if exists, err := s.AdminExists(); err != nil || !exists {
		t.Fatalf("AdminExists after Put: exists=%v err=%v, want true", exists, err)
	}
	got, found, err := s.GetAdmin()
	if err != nil || !found {
		t.Fatalf("GetAdmin: found=%v err=%v", found, err)
	}
	if got.Username != want.Username || got.Hash != want.Hash || !got.CreatedAt.Equal(want.CreatedAt) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestDeleteAdminReArmsSetup(t *testing.T) {
	s := openTemp(t)
	if err := s.PutAdmin(Admin{Username: "a", Hash: "h"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAdmin(); err != nil {
		t.Fatalf("DeleteAdmin: %v", err)
	}
	if exists, _ := s.AdminExists(); exists {
		t.Error("admin still present after DeleteAdmin")
	}
}

func TestSessionRoundTripAndDelete(t *testing.T) {
	s := openTemp(t)
	exp := time.Now().Add(30 * 24 * time.Hour).Truncate(time.Second)
	if err := s.PutSession(Session{ID: "abc", Username: "admin", Expiry: exp}); err != nil {
		t.Fatalf("PutSession: %v", err)
	}
	got, found, err := s.GetSession("abc")
	if err != nil || !found {
		t.Fatalf("GetSession: found=%v err=%v", found, err)
	}
	if got.Username != "admin" || !got.Expiry.Equal(exp) {
		t.Errorf("got %+v, want username=admin expiry=%v", got, exp)
	}
	if err := s.DeleteSession("abc"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, found, _ := s.GetSession("abc"); found {
		t.Error("session present after DeleteSession")
	}
}

func TestClearSessions(t *testing.T) {
	s := openTemp(t)
	for _, id := range []string{"a", "b", "c"} {
		if err := s.PutSession(Session{ID: id, Username: "admin", Expiry: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.ClearSessions(); err != nil {
		t.Fatalf("ClearSessions: %v", err)
	}
	for _, id := range []string{"a", "b", "c"} {
		if _, found, _ := s.GetSession(id); found {
			t.Errorf("session %q survived ClearSessions", id)
		}
	}
}
