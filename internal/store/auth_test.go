package store

import (
	"errors"
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
	if err := s.CreateAdmin(want); err != nil {
		t.Fatalf("CreateAdmin: %v", err)
	}
	if exists, err := s.AdminExists(); err != nil || !exists {
		t.Fatalf("AdminExists after Create: exists=%v err=%v, want true", exists, err)
	}
	got, found, err := s.GetAdmin()
	if err != nil || !found {
		t.Fatalf("GetAdmin: found=%v err=%v", found, err)
	}
	if got.Username != want.Username || got.Hash != want.Hash || !got.CreatedAt.Equal(want.CreatedAt) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestCreateAdminRefusesSecond(t *testing.T) {
	s := openTemp(t)
	if err := s.CreateAdmin(Admin{Username: "first", Hash: "h1"}); err != nil {
		t.Fatalf("first CreateAdmin: %v", err)
	}
	if err := s.CreateAdmin(Admin{Username: "second", Hash: "h2"}); !errors.Is(err, ErrAdminExists) {
		t.Fatalf("second CreateAdmin err = %v, want ErrAdminExists", err)
	}
	if got, _, _ := s.GetAdmin(); got.Username != "first" {
		t.Errorf("admin = %q, want the first one kept", got.Username)
	}
}

func TestChangePasswordIsConditionalOnEpoch(t *testing.T) {
	s := openTemp(t)
	if err := s.CreateAdmin(Admin{Username: "admin", Hash: "old", Epoch: 4}); err != nil {
		t.Fatal(err)
	}
	got, err := s.ChangePassword(4, "new")
	if err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	if got.Hash != "new" || got.Epoch != 5 {
		t.Errorf("got hash=%q epoch=%d, want new and 5", got.Hash, got.Epoch)
	}
	// A racing change that read epoch 4 must not land on top.
	if _, err := s.ChangePassword(4, "racer"); !errors.Is(err, ErrAdminChanged) {
		t.Fatalf("stale ChangePassword err = %v, want ErrAdminChanged", err)
	}
	if a, _, _ := s.GetAdmin(); a.Hash != "new" || a.Epoch != 5 {
		t.Errorf("stored hash=%q epoch=%d, want new and 5", a.Hash, a.Epoch)
	}
}

func TestExtendSessionSkipsDeleted(t *testing.T) {
	s := openTemp(t)
	exp := time.Now().Add(time.Hour).Truncate(time.Second)
	if err := s.PutSession(Session{ID: "abc", Username: "admin", Expiry: exp, Epoch: 2}); err != nil {
		t.Fatal(err)
	}
	later := exp.Add(24 * time.Hour)
	if found, err := s.ExtendSession("abc", later); err != nil || !found {
		t.Fatalf("ExtendSession: found=%v err=%v", found, err)
	}
	if got, _, _ := s.GetSession("abc"); !got.Expiry.Equal(later) || got.Epoch != 2 {
		t.Errorf("got expiry=%v epoch=%d, want %v and 2", got.Expiry, got.Epoch, later)
	}
	// Logout won the race: the refresh must not write the session back.
	if err := s.DeleteSession("abc"); err != nil {
		t.Fatal(err)
	}
	if found, err := s.ExtendSession("abc", later); err != nil || found {
		t.Fatalf("ExtendSession after delete: found=%v err=%v, want false", found, err)
	}
	if _, found, _ := s.GetSession("abc"); found {
		t.Error("deleted session was written back")
	}
}

func TestDeleteAdminReArmsSetup(t *testing.T) {
	s := openTemp(t)
	if err := s.CreateAdmin(Admin{Username: "a", Hash: "h"}); err != nil {
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
