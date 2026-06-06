package baseline

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/meedoomostafa/devdiag/internal/schema"
	"gopkg.in/yaml.v3"
)

// SchemaVersion is the required schema version for baseline files.
const SchemaVersion = "devdiag.baseline/v1"

// Entry represents a single suppressed finding in a baseline file.
type Entry struct {
	ID        string     `json:"id" yaml:"id"`
	Reason    string     `json:"reason,omitempty" yaml:"reason,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
	CreatedAt time.Time  `json:"created_at" yaml:"created_at"`
	CreatedBy string     `json:"created_by,omitempty" yaml:"created_by,omitempty"`
}

// Baseline represents a baseline file containing suppressed findings.
type Baseline struct {
	SchemaVersion string  `json:"schema_version" yaml:"schema_version"`
	Entries       []Entry `json:"entries" yaml:"entries"`
}

// CreateOptions controls baseline creation from findings.
type CreateOptions struct {
	Reason      string
	CreatedAt   time.Time
	CreatedBy   string
	ExpiresAt   *time.Time
	MinSeverity schema.Severity
}

// DefaultPath returns the default baseline file path under the project root.
func DefaultPath(projectRoot string) string {
	return filepath.Join(projectRoot, ".devdiag", "baseline.yaml")
}

// Load reads and validates a baseline file. Missing files and empty files
// return an empty Baseline with nil error. Invalid YAML or bad schema
// returns an error.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &Baseline{SchemaVersion: SchemaVersion}, nil
		}
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return &Baseline{SchemaVersion: SchemaVersion}, nil
	}
	var b Baseline
	if err := yaml.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse baseline YAML: %w", err)
	}
	if err := validate(&b); err != nil {
		return nil, err
	}
	return &b, nil
}

// validate checks baseline invariants.
func validate(b *Baseline) error {
	if b.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported baseline schema version %q (expected %q)", b.SchemaVersion, SchemaVersion)
	}
	for i, entry := range b.Entries {
		if strings.TrimSpace(entry.ID) == "" {
			return fmt.Errorf("baseline entry %d has empty id", i)
		}
		if entry.CreatedAt.IsZero() {
			return fmt.Errorf("baseline entry %d (%s) has zero created_at", i, entry.ID)
		}
	}
	return nil
}

// Save writes a baseline file with owner-only permissions.
// Parent directories are created with 0700 permissions.
func Save(path string, b *Baseline) error {
	// Sort entries by ID for deterministic diffs.
	sorted := make([]Entry, len(b.Entries))
	copy(sorted, b.Entries)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})
	toSave := &Baseline{
		SchemaVersion: b.SchemaVersion,
		Entries:       sorted,
	}

	data, err := yaml.Marshal(toSave)
	if err != nil {
		return fmt.Errorf("marshal baseline: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create baseline directory: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("set baseline directory permissions: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write baseline: %w", err)
	}
	return os.Chmod(path, 0600)
}

// ActiveEntries returns entries that are not expired as of the given time.
func ActiveEntries(b *Baseline, now time.Time) []Entry {
	if b == nil {
		return nil
	}
	active := make([]Entry, 0, len(b.Entries))
	for _, entry := range b.Entries {
		if entry.ExpiresAt != nil && entry.ExpiresAt.Before(now) {
			continue
		}
		active = append(active, entry)
	}
	return active
}

// CreateFromFindings snapshots findings into baseline entries.
// Duplicate finding IDs produce a single entry. Findings with empty IDs
// are ignored. Entries are sorted by ID for deterministic output.
func CreateFromFindings(findings []schema.Finding, opts CreateOptions) *Baseline {
	seen := make(map[string]bool, len(findings))
	entries := make([]Entry, 0, len(findings))
	minRank := severityRank(opts.MinSeverity)
	for _, f := range findings {
		id := strings.TrimSpace(f.ID)
		if id == "" || seen[id] {
			continue
		}
		if severityRank(f.Severity) < minRank {
			continue
		}
		seen[id] = true
		entry := Entry{
			ID:        id,
			Reason:    opts.Reason,
			CreatedAt: opts.CreatedAt,
			CreatedBy: opts.CreatedBy,
		}
		if opts.ExpiresAt != nil {
			t := *opts.ExpiresAt
			entry.ExpiresAt = &t
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].ID < entries[j].ID
	})
	return &Baseline{
		SchemaVersion: SchemaVersion,
		Entries:       entries,
	}
}

// ParseExpiryDuration parses a human-friendly duration string supporting
// d (days), h (hours), and m (minutes) suffixes. It returns the absolute
// expiry time computed from now. Examples: "30d", "12h", "90m".
func ParseExpiryDuration(raw string, now time.Time) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, errors.New("empty expiry duration")
	}
	if len(raw) < 2 {
		return time.Time{}, fmt.Errorf("invalid expiry duration %q", raw)
	}
	unit := raw[len(raw)-1]
	numStr := raw[:len(raw)-1]
	n, err := strconv.Atoi(numStr)
	if err != nil || n <= 0 {
		return time.Time{}, fmt.Errorf("invalid expiry duration %q: value must be a positive integer", raw)
	}
	switch unit {
	case 'd':
		return now.Add(time.Duration(n) * 24 * time.Hour), nil
	case 'h':
		return now.Add(time.Duration(n) * time.Hour), nil
	case 'm':
		return now.Add(time.Duration(n) * time.Minute), nil
	default:
		return time.Time{}, fmt.Errorf("invalid expiry duration %q: supported units are d (days), h (hours), m (minutes)", raw)
	}
}

func severityRank(severity schema.Severity) int {
	switch severity {
	case schema.SeverityCritical:
		return 4
	case schema.SeverityHigh:
		return 3
	case schema.SeverityMedium:
		return 2
	case schema.SeverityLow:
		return 1
	case schema.SeverityInfo:
		return 0
	default:
		return -1
	}
}
