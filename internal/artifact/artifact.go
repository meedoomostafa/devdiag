package artifact

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	DirPerm  = 0700
	FilePerm = 0600
)

var ErrNoRunsFound = errors.New("no .devdiag/runs directory found in ancestors")

// RunsDir returns the .devdiag/runs directory under base.
func RunsDir(base string) string {
	return filepath.Join(base, ".devdiag", "runs")
}

// RunDir returns the directory for a specific run ID under base.
func RunDir(base, runID string) string {
	return filepath.Join(RunsDir(base), runID)
}

// LatestLink returns the path to the 'latest' symlink under base.
func LatestLink(base string) string {
	return filepath.Join(RunsDir(base), "latest")
}

// DiscoverBase walks upward from start looking for .devdiag/runs.
func DiscoverBase(start string) (string, error) {
	abs, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}

	curr := abs
	for {
		if _, err := os.Stat(filepath.Join(curr, ".devdiag", "runs")); err == nil {
			return curr, nil
		}

		parent := filepath.Dir(curr)
		if parent == curr {
			break
		}
		curr = parent
	}

	return "", ErrNoRunsFound
}

// MkdirPrivate creates a directory with owner-only permissions.
func MkdirPrivate(path string) error {
	if err := os.MkdirAll(path, DirPerm); err != nil {
		return err
	}
	return os.Chmod(path, DirPerm)
}

// WriteFilePrivate writes a file with owner-only permissions.
func WriteFilePrivate(path string, data []byte) error {
	if err := MkdirPrivate(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.WriteFile(path, data, FilePerm); err != nil {
		return err
	}
	return os.Chmod(path, FilePerm)
}

// FindLatestRunID returns the run ID pointed to by the latest symlink or the most recent directory.
func FindLatestRunID(base string) (string, error) {
	runs := RunsDir(base)

	// Try latest symlink first
	latest := LatestLink(base)
	if target, err := os.Readlink(latest); err == nil {
		targetID := target
		if filepath.IsAbs(target) {
			rel, err := filepath.Rel(runs, target)
			if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
				return "", fmt.Errorf("latest symlink points outside runs dir: %s", target)
			}
			targetID = rel
		}
		if err := ValidateRunID(targetID); err != nil {
			return "", fmt.Errorf("invalid run ID in latest symlink: %w", err)
		}
		return targetID, nil
	}

	// Fallback to most recent directory by mod time
	entries, err := os.ReadDir(runs)
	if err != nil {
		return "", err
	}

	var bestID string
	var bestTime os.FileInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if err := ValidateRunID(entry.Name()); err != nil {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if bestTime == nil || info.ModTime().After(bestTime.ModTime()) {
			bestTime = info
			bestID = entry.Name()
		}
	}

	if bestID == "" {
		return "", fmt.Errorf("no valid runs found in %s", runs)
	}
	return bestID, nil
}

// ValidateRunID ensures a run ID is a simple alphanumeric string (no traversal).
func ValidateRunID(id string) error {
	if id == "" {
		return errors.New("run ID is empty")
	}
	if strings.ContainsAny(id, `/\.`) || id == "latest" {
		return fmt.Errorf("invalid run ID: %s", id)
	}
	return nil
}
