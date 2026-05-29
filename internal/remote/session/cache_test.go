package session

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/remote/target"
)

func TestCacheRoundTrip(t *testing.T) {
	// Set XDG_CACHE_HOME to a temp dir for isolation
	tmp := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmp)

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
}

func TestWriteCache_Permissions(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmp)

	m := &Manifest{
		SessionID: "test-perm",
		Target:    target.Target{Kind: target.KindSSH, Raw: "user@host"},
	}

	// 1. Test creation permissions
	if err := WriteCache(m); err != nil {
		t.Fatalf("WriteCache error: %v", err)
	}

	cacheDir := CacheDir()
	dirInfo, err := os.Stat(cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0700 {
		t.Errorf("Cache dir perm = %o, want 0700", perm)
	}

	manifestPath := filepath.Join(cacheDir, "ssh_test-perm.json")
	fileInfo, err := os.Stat(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fileInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("Manifest file perm = %o, want 0600", perm)
	}

	// 2. Test repair of permissive files
	if err := os.Chmod(cacheDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(manifestPath, 0644); err != nil {
		t.Fatal(err)
	}

	if err := WriteCache(m); err != nil {
		t.Fatalf("WriteCache error on repair: %v", err)
	}

	dirInfo, _ = os.Stat(cacheDir)
	if perm := dirInfo.Mode().Perm(); perm != 0700 {
		t.Errorf("Repaired cache dir perm = %o, want 0700", perm)
	}

	fileInfo, _ = os.Stat(manifestPath)
	if perm := fileInfo.Mode().Perm(); perm != 0600 {
		t.Errorf("Repaired manifest file perm = %o, want 0600", perm)
	}
}

func TestHashTarget_Stability(t *testing.T) {
	h1 := hashTarget("user@host")
	h2 := hashTarget("user@host")
	if h1 != h2 {
		t.Errorf("hash not stable: %q vs %q", h1, h2)
	}
}
