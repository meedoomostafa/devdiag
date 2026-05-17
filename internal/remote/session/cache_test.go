package session

import (
	"os"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/remote/target"
)

func TestCacheRoundTrip(t *testing.T) {
	m := &Manifest{
		SchemaVersion: "0.1",
		SessionID:     "20260516T203500Z_a19f3c",
		CreatedAt:     "2026-05-16T20:35:00Z",
		Profile:       "minimal",
		Mode:          "temporary",
		RootDir:       "~/.devdiag/remote/20260516T203500Z_a19f3c",
		Status:        "active",
		Target:        target.Target{Kind: target.KindSSH, Raw: "user@host", User: "user", Host: "host"},
		Files:         []ManagedFile{{Path: "env.sh", Mode: "0644", Created: true}},
	}

	if err := WriteCache(m); err != nil {
		t.Fatalf("WriteCache error: %v", err)
	}

	read, err := ReadCache(string(target.KindSSH), "user@host")
	if err != nil {
		t.Fatalf("ReadCache error: %v", err)
	}
	if read.SessionID != m.SessionID {
		t.Errorf("SessionID = %q, want %q", read.SessionID, m.SessionID)
	}
	if read.Profile != m.Profile {
		t.Errorf("Profile = %q, want %q", read.Profile, m.Profile)
	}
	if read.Target.User != m.Target.User {
		t.Errorf("Target.User = %q, want %q", read.Target.User, m.Target.User)
	}

	// Read by session ID
	byID, err := ReadCacheBySessionID(m.SessionID)
	if err != nil {
		t.Fatalf("ReadCacheBySessionID error: %v", err)
	}
	if byID.SessionID != m.SessionID {
		t.Errorf("byID SessionID = %q, want %q", byID.SessionID, m.SessionID)
	}

	// Cleanup
	os.RemoveAll(CacheDir())
}

func TestHashTarget_Stability(t *testing.T) {
	h1 := hashTarget("user@host")
	h2 := hashTarget("user@host")
	if h1 != h2 {
		t.Errorf("hash not stable: %q vs %q", h1, h2)
	}
}
