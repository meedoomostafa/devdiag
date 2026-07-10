package session

import (
	"encoding/json"
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
		Target:        target.Target{Kind: target.KindSSH, Raw: "user@host", User: "user", Host: "host", Port: 22},
		Files:         []ManagedFile{{Path: "~/.devdiag/remote/20260516T203500Z_a19f3c/env.sh", Mode: "0644", Created: true}},
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

func TestValidateManifest(t *testing.T) {
	valid := &Manifest{
		SchemaVersion: "0.1",
		SessionID:     "20260516T203500Z_a19f3c",
		Target:        target.Target{Kind: target.KindSSH, Raw: "user@host", Host: "host"},
		RootDir:       "~/.devdiag/remote/session1",
		Status:        "active",
	}

	if err := ValidateManifest(valid); err != nil {
		t.Errorf("expected valid manifest, got error: %v", err)
	}

	descriptiveID := *valid
	descriptiveID.SessionID = "20260516T203500Z_sessionA"
	descriptiveID.RootDir = "~/.devdiag/remote/20260516T203500Z_sessionA"
	if err := ValidateManifest(&descriptiveID); err != nil {
		t.Errorf("expected descriptive session suffix to be valid, got error: %v", err)
	}

	// 1. Invalid SessionID
	m := *valid
	m.SessionID = "bad-id"
	if err := ValidateManifest(&m); err == nil {
		t.Error("expected error for invalid session ID")
	}

	// 2. Traversal in SessionID
	m = *valid
	m.SessionID = "20260516T203500Z_../../evil"
	if err := ValidateManifest(&m); err == nil {
		t.Error("expected error for traversal in session ID")
	}

	m = *valid
	m.SessionID = "20260516T203500Z_bad;suffix"
	if err := ValidateManifest(&m); err == nil {
		t.Error("expected error for shell metacharacter in session ID")
	}

	// 3. Invalid SchemaVersion
	m = *valid
	m.SchemaVersion = "0.2"
	if err := ValidateManifest(&m); err == nil {
		t.Error("expected error for unsupported schema version")
	}

	// 4. Invalid RootDir
	m = *valid
	m.RootDir = "/etc"
	if err := ValidateManifest(&m); err == nil {
		t.Error("expected error for unsafe root dir")
	}
}

func TestValidateManifestIdentity_AllowsUnsafeRootForExplicitCleanRefusal(t *testing.T) {
	m := &Manifest{
		SchemaVersion: "0.1",
		SessionID:     "20260516T203500Z_sessionA",
		Target:        target.Target{Kind: target.KindK8s, Raw: "k8s:default/api-pod", Namespace: "default", Pod: "api-pod"},
		RootDir:       "~/.devdiag/remote/20260516T203500Z_sessionA",
		Status:        "active",
	}

	if err := ValidateManifestIdentity(m); err != nil {
		t.Fatalf("identity validation should allow unsafe root for later clean refusal: %v", err)
	}
	if err := ValidateManifest(m); err == nil {
		t.Fatal("full manifest validation should reject unsafe k8s root")
	}
}

func TestReadCache_SkipsInvalid(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmp)

	// Write a valid and an invalid manifest directly
	dir := CacheDir()
	os.MkdirAll(dir, 0700)

	valid := Manifest{
		SchemaVersion: "0.1",
		SessionID:     "20260516T203500Z_aaaaaa",
		Target:        target.Target{Kind: target.KindSSH, Raw: "user@host", Host: "host"},
		RootDir:       "~/.devdiag/remote/aaaaaa",
		Status:        "active",
	}
	data, _ := json.Marshal(valid)
	os.WriteFile(filepath.Join(dir, "ssh_20260516T203500Z_aaaaaa.json"), data, 0600)

	invalid := valid
	invalid.SessionID = "20260516T203500Z_bbbbbb"
	invalid.SchemaVersion = "99.9"
	data, _ = json.Marshal(invalid)
	os.WriteFile(filepath.Join(dir, "ssh_20260516T203500Z_bbbbbb.json"), data, 0600)

	// ReadCache should skip the invalid one and return the valid one
	got, err := ReadCache("ssh", "user@host")
	if err != nil {
		t.Fatalf("ReadCache failed: %v", err)
	}
	if got.SessionID != valid.SessionID {
		t.Errorf("got session %s, want %s", got.SessionID, valid.SessionID)
	}
}

func TestWriteCache_Permissions(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", tmp)

	m := &Manifest{
		SchemaVersion: "0.1",
		SessionID:     "20260516T203500Z_abcdef",
		Target:        target.Target{Kind: target.KindSSH, Raw: "user@host", Host: "host", Port: 22},
		RootDir:       "~/.devdiag/remote/20260516T203500Z_abcdef",
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

	manifestPath := filepath.Join(cacheDir, "ssh_20260516T203500Z_abcdef.json")
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


