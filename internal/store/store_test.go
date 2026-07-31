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
		Ref:                  "gitea/gitea:1.24.3",
		Kind:                 "SEMVER",
		Current:              "1.24.3",
		Latest:               "1.25.0",
		UpdateKind:           "minor",
		Status:               StatusOK,
		CheckedAt:            now,
		RepublishedAt:        now.Add(-time.Hour),
		RepublishedEstimated: true,
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
	if !got.RepublishedAt.Equal(want.RepublishedAt) || got.RepublishedEstimated != want.RepublishedEstimated {
		t.Errorf("republish fields = %v %v, want %v %v",
			got.RepublishedAt, got.RepublishedEstimated, want.RepublishedAt, want.RepublishedEstimated)
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
	want := AgentStatus{
		Name: "home", LastOK: true, LastPoll: now, LastSuccess: now, ConsecutiveFailures: 0, DownNotified: false,
		LastWireV: 1, WireNotifiedV: 2, CertNotAfter: now.Add(time.Hour), LastRenewalReminder: now,
	}
	if err := s.PutAgent(want); err != nil {
		t.Fatalf("PutAgent: %v", err)
	}
	got, found, err := s.GetAgent("home")
	if err != nil || !found {
		t.Fatalf("GetAgent: found=%v err=%v", found, err)
	}
	if got.LastOK != want.LastOK || got.ConsecutiveFailures != want.ConsecutiveFailures ||
		!got.LastPoll.Equal(want.LastPoll) || !got.LastSuccess.Equal(want.LastSuccess) {
		t.Errorf("got %+v, want %+v", got, want)
	}
	if got.LastWireV != want.LastWireV || got.WireNotifiedV != want.WireNotifiedV ||
		!got.CertNotAfter.Equal(want.CertNotAfter) || !got.LastRenewalReminder.Equal(want.LastRenewalReminder) {
		t.Errorf("new fields not round-tripped: got %+v, want %+v", got, want)
	}
}

func TestPruneAgents(t *testing.T) {
	s := openTemp(t)
	for _, n := range []string{"home", "pi", "nas"} {
		if err := s.PutAgent(AgentStatus{Name: n, LastOK: true}); err != nil {
			t.Fatalf("PutAgent %s: %v", n, err)
		}
	}

	// "pi" was renamed to "pi4" in the config and never polled under the old name.
	removed, err := s.PruneAgents([]string{"home", "nas", "pi4"})
	if err != nil {
		t.Fatalf("PruneAgents: %v", err)
	}
	if len(removed) != 1 || removed[0] != "pi" {
		t.Errorf("removed = %v, want [pi]", removed)
	}
	if _, found, _ := s.GetAgent("pi"); found {
		t.Error("pi still stored; its card would linger on the agents page")
	}
	for _, n := range []string{"home", "nas"} {
		if _, found, _ := s.GetAgent(n); !found {
			t.Errorf("%s was pruned but is still configured", n)
		}
	}

	// A configured agent with no stored status yet is not an error.
	if removed, err := s.PruneAgents([]string{"home", "nas", "pi4"}); err != nil || len(removed) != 0 {
		t.Errorf("second prune: removed=%v err=%v, want none", removed, err)
	}
}

func TestPruneAgentsEmptyConfigClearsAll(t *testing.T) {
	s := openTemp(t)
	if err := s.PutAgent(AgentStatus{Name: "home"}); err != nil {
		t.Fatal(err)
	}
	removed, err := s.PruneAgents(nil)
	if err != nil || len(removed) != 1 {
		t.Fatalf("removed=%v err=%v, want [home]", removed, err)
	}
	all, err := s.AllAgents()
	if err != nil || len(all) != 0 {
		t.Errorf("AllAgents = %v (err %v), want empty", all, err)
	}
}

func TestCAKeyMissingGate(t *testing.T) {
	s := openTemp(t)
	if set, err := s.CAKeyMissingNotified(); err != nil || set {
		t.Fatalf("fresh store: notified=%v err=%v, want false", set, err)
	}
	if err := s.SetCAKeyMissingNotified(true); err != nil {
		t.Fatal(err)
	}
	if set, err := s.CAKeyMissingNotified(); err != nil || !set {
		t.Errorf("after set: notified=%v err=%v, want true", set, err)
	}
	if err := s.SetCAKeyMissingNotified(false); err != nil {
		t.Fatal(err)
	}
	if set, err := s.CAKeyMissingNotified(); err != nil || set {
		t.Errorf("after clear: notified=%v err=%v, want false", set, err)
	}
}

func TestNotifiedRoundTrip(t *testing.T) {
	s := openTemp(t)
	now := time.Now().Truncate(time.Second)
	want := NotifiedState{Ref: "gitea/gitea:1.24.3", Version: "1.25.0", Digest: "sha256:idx", NotifiedAt: now}
	if err := s.PutNotified(want); err != nil {
		t.Fatalf("PutNotified: %v", err)
	}
	got, found, err := s.GetNotified(want.Ref)
	if err != nil || !found {
		t.Fatalf("GetNotified: found=%v err=%v", found, err)
	}
	if got.Version != want.Version || got.Digest != want.Digest || !got.NotifiedAt.Equal(want.NotifiedAt) {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestGetNotifiedMissing(t *testing.T) {
	s := openTemp(t)
	if _, found, err := s.GetNotified("nope:1"); err != nil || found {
		t.Errorf("found=%v err=%v, want found=false err=nil", found, err)
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
