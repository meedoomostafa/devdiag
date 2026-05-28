package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CacheDir returns the local cache directory for remote sessions.
func CacheDir() string {
	cacheHome := os.Getenv("XDG_CACHE_HOME")
	if cacheHome == "" {
		home := os.Getenv("HOME")
		if home == "" {
			return "/tmp/devdiag-cache/remote/sessions"
		}
		cacheHome = filepath.Join(home, ".cache")
	}
	return filepath.Join(cacheHome, "devdiag", "remote", "sessions")
}

// WriteCache writes a manifest to the local session cache keyed by session ID.
func WriteCache(manifest *Manifest) error {
	dir := CacheDir()
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("mkdir cache: %w", err)
	}

	filename := fmt.Sprintf("%s_%s.json", manifest.Target.Kind, manifest.SessionID)
	path := filepath.Join(dir, filename)

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write cache: %w", err)
	}
	return nil
}

// ReadCache reads the latest cached manifest for a target.
func ReadCache(kind, raw string) (*Manifest, error) {
	dir := CacheDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var latest *Manifest
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		// Filter by kind prefix
		if !strings.HasPrefix(entry.Name(), kind+"_") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		var m Manifest
		if err := json.Unmarshal(data, &m); err != nil {
			continue
		}
		if m.Target.Raw != raw {
			continue
		}
		if latest == nil || m.CreatedAt > latest.CreatedAt {
			latest = &m
		}
	}
	if latest == nil {
		return nil, fmt.Errorf("no cached session found for %s %s", kind, raw)
	}
	return latest, nil
}

// ListCache returns all cached manifests matching the target.
func ListCache(kind, raw string) ([]*Manifest, error) {
	dir := CacheDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var results []*Manifest
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		// Filter by kind prefix
		if !strings.HasPrefix(entry.Name(), kind+"_") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		var m Manifest
		if err := json.Unmarshal(data, &m); err != nil {
			continue
		}
		if m.Target.Raw != raw {
			continue
		}
		results = append(results, &m)
	}
	return results, nil
}

// ReadCacheBySessionID searches all cached manifests for the given session ID.
func ReadCacheBySessionID(sessionID string) (*Manifest, error) {
	dir := CacheDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		var m Manifest
		if err := json.Unmarshal(data, &m); err != nil {
			continue
		}
		if m.SessionID == sessionID {
			return &m, nil
		}
	}
	return nil, fmt.Errorf("session %s not found", sessionID)
}

// hashTarget creates a simple stable hash for a target string.
func hashTarget(s string) string {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return fmt.Sprintf("%08x", h)
}
