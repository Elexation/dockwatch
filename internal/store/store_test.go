package store

import (
	"testing"
	"time"
)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCheckRoundTrip(t *testing.T) {
	s := openTemp(t)
	now := time.Now().Truncate(time.Second)
	want := CheckResult{
		Ref:        "gitea/gitea:1.24.3",
		Kind:       "SEMVER",
		Current:    "1.24.3",
		Latest:     "1.25.0",
		UpdateKind: "minor",
		Status:     StatusOK,
		CheckedAt:  now,
	}
	if err := s.PutCheck(want); err != nil {
		t.Fatalf("PutCheck: %v", err)
	}

	got, found, err := s.GetCheck(want.Ref)
	if err != nil || !found {
		t.Fatalf("GetCheck: found=%v err=%v", found, err)
	}
	if got.Latest != want.Latest || got.UpdateKind != want.UpdateKind || got.Status != want.Status {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if !got.CheckedAt.Equal(want.CheckedAt) {
		t.Errorf("CheckedAt = %v, want %v", got.CheckedAt, want.CheckedAt)
	}
}

func TestGetCheckMissing(t *testing.T) {
	s := openTemp(t)
	_, found, err := s.GetCheck("nope:1")
	if err != nil {
		t.Fatalf("GetCheck: %v", err)
	}
	if found {
		t.Errorf("found = true for absent key")
	}
}

func TestAllChecks(t *testing.T) {
	s := openTemp(t)
	for _, ref := range []string{"a:1", "b:2", "c:3"} {
		if err := s.PutCheck(CheckResult{Ref: ref, Status: StatusOK}); err != nil {
			t.Fatalf("PutCheck %s: %v", ref, err)
		}
	}
	all, err := s.AllChecks()
	if err != nil {
		t.Fatalf("AllChecks: %v", err)
	}
	if len(all) != 3 {
		t.Errorf("AllChecks len = %d, want 3", len(all))
	}
}

func TestAgentRoundTrip(t *testing.T) {
	s := openTemp(t)
	now := time.Now().Truncate(time.Second)
	want := AgentStatus{Name: "home", LastOK: true, LastPoll: now, ConsecutiveFailures: 0, DownNotified: false}
	if err := s.PutAgent(want); err != nil {
		t.Fatalf("PutAgent: %v", err)
	}
	got, found, err := s.GetAgent("home")
	if err != nil || !found {
		t.Fatalf("GetAgent: found=%v err=%v", found, err)
	}
	if got.LastOK != want.LastOK || got.ConsecutiveFailures != want.ConsecutiveFailures || !got.LastPoll.Equal(want.LastPoll) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestPersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.PutCheck(CheckResult{Ref: "x:1", Status: StatusOK}); err != nil {
		t.Fatalf("PutCheck: %v", err)
	}
	s.Close()

	s2, err := Open(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	if _, found, _ := s2.GetCheck("x:1"); !found {
		t.Errorf("entry not persisted across reopen")
	}
}
