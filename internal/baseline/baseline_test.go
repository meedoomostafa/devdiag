package baseline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestLoadMissingFileReturnsEmptyBaseline(t *testing.T) {
	b, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b.Entries) != 0 {
		t.Fatalf("expected empty entries, got %d", len(b.Entries))
	}
	if b.SchemaVersion != SchemaVersion {
		t.Fatalf("expected schema version %q, got %q", SchemaVersion, b.SchemaVersion)
	}
}

func TestLoadEmptyFileReturnsEmptyBaseline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.yaml")
	if err := os.WriteFile(path, []byte(""), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	b, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(b.Entries) != 0 {
		t.Fatalf("expected empty entries, got %d", len(b.Entries))
	}
}

func TestLoadInvalidYAMLReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.yaml")
	if err := os.WriteFile(path, []byte("entries: ["), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadWrongSchemaVersionReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.yaml")
	data := []byte(`schema_version: devdiag.baseline/v99
entries: []
`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for wrong schema version")
	}
}

func TestLoadEmptyEntryIDReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.yaml")
	data := []byte(`schema_version: devdiag.baseline/v1
entries:
  - id: ""
    reason: "test"
    created_at: 2026-06-06T12:00:00Z
`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for empty entry ID")
	}
}

func TestLoadZeroCreatedAtReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.yaml")
	data := []byte(`schema_version: devdiag.baseline/v1
entries:
  - id: F-ENV-001
    reason: "test"
`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for zero created_at")
	}
}

func TestLoadValidBaseline(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.yaml")
	data := []byte(`schema_version: devdiag.baseline/v1
entries:
  - id: F-ENV-001
    reason: "accepted for local dev"
    created_at: 2026-06-06T12:00:00Z
    created_by: tester
  - id: F-CI-SHELL-001
    reason: "intentional"
    created_at: 2026-06-06T12:00:00Z
    expires_at: 2027-01-01T00:00:00Z
`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	b, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b.SchemaVersion != SchemaVersion {
		t.Fatalf("schema version = %q, want %q", b.SchemaVersion, SchemaVersion)
	}
	if len(b.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(b.Entries))
	}
	if b.Entries[0].ID != "F-ENV-001" {
		t.Fatalf("first entry ID = %q, want F-ENV-001", b.Entries[0].ID)
	}
	if b.Entries[1].ExpiresAt == nil {
		t.Fatal("second entry should have ExpiresAt set")
	}
}

func TestSaveRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".devdiag", "baseline.yaml")

	now := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	expires := now.Add(30 * 24 * time.Hour)
	b := &Baseline{
		SchemaVersion: SchemaVersion,
		Entries: []Entry{
			{ID: "F-ENV-001", Reason: "test", CreatedAt: now, CreatedBy: "tester"},
			{ID: "F-CI-SHELL-001", Reason: "intentional", CreatedAt: now, ExpiresAt: &expires},
		},
	}
	if err := Save(path, b); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load after save: %v", err)
	}
	if len(loaded.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(loaded.Entries))
	}
}

func TestSaveCreatesParentWithPrivatePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".devdiag", "baseline.yaml")

	b := &Baseline{
		SchemaVersion: SchemaVersion,
		Entries: []Entry{
			{ID: "F-ENV-001", Reason: "test", CreatedAt: time.Now()},
		},
	}
	if err := Save(path, b); err != nil {
		t.Fatalf("save: %v", err)
	}

	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0700 {
		t.Fatalf("dir perm = %o, want 0700", perm)
	}

	finfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if perm := finfo.Mode().Perm(); perm != 0600 {
		t.Fatalf("file perm = %o, want 0600", perm)
	}
}

func TestSaveIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".devdiag", "baseline.yaml")

	now := time.Now().UTC()
	b := &Baseline{
		SchemaVersion: SchemaVersion,
		Entries:       []Entry{{ID: "F-ENV-001", Reason: "test", CreatedAt: now}},
	}
	if err := Save(path, b); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Save writes via a temp file + rename so a crash mid-write can never
	// leave a truncated baseline. Verify no temp artifacts remain.
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, entry := range entries {
		if entry.Name() != "baseline.yaml" {
			t.Fatalf("unexpected leftover file %q after save", entry.Name())
		}
	}

	// Overwrite must also go through rename, preserving previous content on
	// reload even after repeated saves.
	b.Entries = append(b.Entries, Entry{ID: "F-CI-001", Reason: "second", CreatedAt: now})
	if err := Save(path, b); err != nil {
		t.Fatalf("second save: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(loaded.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(loaded.Entries))
	}
}

func TestSaveEntriesSortedByID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.yaml")

	now := time.Now().UTC()
	b := &Baseline{
		SchemaVersion: SchemaVersion,
		Entries: []Entry{
			{ID: "F-ENV-001", Reason: "b", CreatedAt: now},
			{ID: "F-CI-SHELL-001", Reason: "a", CreatedAt: now},
		},
	}
	if err := Save(path, b); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Entries[0].ID != "F-CI-SHELL-001" {
		t.Fatalf("entries not sorted: first = %q, want F-CI-SHELL-001", loaded.Entries[0].ID)
	}
}

func TestActiveEntriesFiltersExpired(t *testing.T) {
	now := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	past := now.Add(-24 * time.Hour)
	future := now.Add(24 * time.Hour)
	b := &Baseline{
		SchemaVersion: SchemaVersion,
		Entries: []Entry{
			{ID: "F-EXPIRED", Reason: "old", CreatedAt: now, ExpiresAt: &past},
			{ID: "F-ACTIVE", Reason: "current", CreatedAt: now, ExpiresAt: &future},
			{ID: "F-NO-EXPIRY", Reason: "forever", CreatedAt: now},
		},
	}
	active := ActiveEntries(b, now)
	if len(active) != 2 {
		t.Fatalf("active = %d, want 2", len(active))
	}
	for _, e := range active {
		if e.ID == "F-EXPIRED" {
			t.Fatal("expired entry should not be active")
		}
	}
}

func TestActiveEntriesNilBaseline(t *testing.T) {
	active := ActiveEntries(nil, time.Now())
	if active != nil {
		t.Fatalf("expected nil, got %v", active)
	}
}

func TestCreateFromFindings(t *testing.T) {
	now := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	findings := []schema.Finding{
		{ID: "F-ENV-001", Severity: schema.SeverityMedium},
		{ID: "F-CI-SHELL-001", Severity: schema.SeverityHigh},
	}
	b := CreateFromFindings(findings, CreateOptions{
		Reason:    "accepted for v1.0",
		CreatedAt: now,
		CreatedBy: "tester",
	})
	if b.SchemaVersion != SchemaVersion {
		t.Fatalf("schema = %q, want %q", b.SchemaVersion, SchemaVersion)
	}
	if len(b.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(b.Entries))
	}
	// Should be sorted
	if b.Entries[0].ID != "F-CI-SHELL-001" {
		t.Fatalf("entries not sorted: first = %q", b.Entries[0].ID)
	}
}

func TestCreateFromFindingsDeduplicates(t *testing.T) {
	now := time.Now()
	findings := []schema.Finding{
		{ID: "F-ENV-001", Severity: schema.SeverityMedium},
		{ID: "F-ENV-001", Severity: schema.SeverityMedium},
	}
	b := CreateFromFindings(findings, CreateOptions{
		Reason:    "test",
		CreatedAt: now,
	})
	if len(b.Entries) != 1 {
		t.Fatalf("entries = %d, want 1 (deduplicated)", len(b.Entries))
	}
}

func TestCreateFromFindingsIgnoresEmptyIDs(t *testing.T) {
	now := time.Now()
	findings := []schema.Finding{
		{ID: "", Severity: schema.SeverityMedium},
		{ID: "F-ENV-001", Severity: schema.SeverityMedium},
	}
	b := CreateFromFindings(findings, CreateOptions{
		Reason:    "test",
		CreatedAt: now,
	})
	if len(b.Entries) != 1 {
		t.Fatalf("entries = %d, want 1 (empty ID skipped)", len(b.Entries))
	}
}

func TestCreateFromFindingsFiltersByMinSeverity(t *testing.T) {
	now := time.Now()
	findings := []schema.Finding{
		{ID: "F-LOW-001", Severity: schema.SeverityLow},
		{ID: "F-MED-001", Severity: schema.SeverityMedium},
		{ID: "F-HIGH-001", Severity: schema.SeverityHigh},
	}
	b := CreateFromFindings(findings, CreateOptions{
		Reason:      "test",
		CreatedAt:   now,
		MinSeverity: schema.SeverityMedium,
	})
	if len(b.Entries) != 2 {
		t.Fatalf("entries = %d, want 2 (low filtered out)", len(b.Entries))
	}
	for _, e := range b.Entries {
		if e.ID == "F-LOW-001" {
			t.Fatal("low severity finding should be filtered out")
		}
	}
}

func TestCreateFromFindingsWithExpiry(t *testing.T) {
	now := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	expires := now.Add(30 * 24 * time.Hour)
	findings := []schema.Finding{
		{ID: "F-ENV-001", Severity: schema.SeverityMedium},
	}
	b := CreateFromFindings(findings, CreateOptions{
		Reason:    "test",
		CreatedAt: now,
		ExpiresAt: &expires,
	})
	if len(b.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(b.Entries))
	}
	if b.Entries[0].ExpiresAt == nil {
		t.Fatal("expected ExpiresAt to be set")
	}
	if !b.Entries[0].ExpiresAt.Equal(expires) {
		t.Fatalf("ExpiresAt = %v, want %v", b.Entries[0].ExpiresAt, expires)
	}
}

// --- ParseExpiryDuration tests ---

func TestParseExpiryDurationDays(t *testing.T) {
	now := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	got, err := ParseExpiryDuration("30d", now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := now.Add(30 * 24 * time.Hour)
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseExpiryDurationHours(t *testing.T) {
	now := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	got, err := ParseExpiryDuration("12h", now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := now.Add(12 * time.Hour)
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseExpiryDurationMinutes(t *testing.T) {
	now := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	got, err := ParseExpiryDuration("90m", now)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := now.Add(90 * time.Minute)
	if !got.Equal(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseExpiryDurationRejectsInvalid(t *testing.T) {
	now := time.Now()
	for _, input := range []string{"", "30", "abc", "30x", "-5d", "0d"} {
		_, err := ParseExpiryDuration(input, now)
		if err == nil {
			t.Fatalf("expected error for input %q", input)
		}
	}
}

func TestFingerprintNormalizesID(t *testing.T) {
	f1 := schema.Finding{ID: "f-env-001", Symptom: "test"}
	f2 := schema.Finding{ID: " F-ENV-001 ", Symptom: "test"}

	fp1 := Fingerprint(f1)
	fp2 := Fingerprint(f2)
	if fp1 != fp2 {
		t.Fatalf("expected fingerprints to match normalized ID, got %q and %q", fp1, fp2)
	}
}

func TestLoadRejectsInvalidFingerprint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.yaml")
	data := []byte(`schema_version: devdiag.baseline/v1
entries:
  - id: F-ENV-001
    reason: "test"
    created_at: 2026-06-06T12:00:00Z
    fingerprint: "invalidhex123"
`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid fingerprint on load")
	}
}

func TestLoadAcceptsValidFingerprint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.yaml")
	validFP := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	data := []byte(`schema_version: devdiag.baseline/v1
entries:
  - id: F-ENV-001
    reason: "test"
    created_at: 2026-06-06T12:00:00Z
    fingerprint: "` + validFP + `"
`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	b, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if b.Entries[0].Fingerprint != validFP {
		t.Fatalf("loaded fingerprint = %q, want %q", b.Entries[0].Fingerprint, validFP)
	}
}

func TestCreateFromFindingsWithoutFingerprintDeduplicatesByID(t *testing.T) {
	findings := []schema.Finding{
		{ID: "F-ENV-001", Symptom: "test 1"},
		{ID: "F-ENV-001", Symptom: "test 2"},
	}
	b := CreateFromFindings(findings, CreateOptions{
		Reason:    "test",
		CreatedAt: time.Now(),
	})
	if len(b.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(b.Entries))
	}
}

func TestCreateFromFindingsWithFingerprintKeepsSameIDDifferentSymptoms(t *testing.T) {
	findings := []schema.Finding{
		{ID: "F-ENV-001", Symptom: "test 1"},
		{ID: "F-ENV-001", Symptom: "test 2"},
	}
	b := CreateFromFindings(findings, CreateOptions{
		Reason:         "test",
		CreatedAt:      time.Now(),
		UseFingerprint: true,
	})
	if len(b.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(b.Entries))
	}
	if b.Entries[0].Fingerprint == "" || b.Entries[1].Fingerprint == "" {
		t.Fatal("expected non-empty fingerprints in entries")
	}
	if b.Entries[0].Fingerprint == b.Entries[1].Fingerprint {
		t.Fatal("expected different fingerprints for different symptoms")
	}
}

func TestCreateFromFindingsWithFingerprintDeduplicatesSameIDAndSameSymptom(t *testing.T) {
	findings := []schema.Finding{
		{ID: "F-ENV-001", Symptom: "test 1"},
		{ID: "F-ENV-001", Symptom: "test 1"},
	}
	b := CreateFromFindings(findings, CreateOptions{
		Reason:         "test",
		CreatedAt:      time.Now(),
		UseFingerprint: true,
	})
	if len(b.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(b.Entries))
	}
}

func TestSaveSortsByIDThenFingerprint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.yaml")

	now := time.Now().UTC()
	fpAAA := "aaa" + strings.Repeat("0", 61)
	fpBBB := "bbb" + strings.Repeat("0", 61)
	fpCCC := "ccc" + strings.Repeat("0", 61)

	b := &Baseline{
		SchemaVersion: SchemaVersion,
		Entries: []Entry{
			{ID: "F-ENV-001", Fingerprint: fpBBB, CreatedAt: now},
			{ID: "F-ENV-001", Fingerprint: fpAAA, CreatedAt: now},
			{ID: "F-CI", Fingerprint: fpCCC, CreatedAt: now},
		},
	}
	if err := Save(path, b); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if loaded.Entries[0].ID != "F-CI" {
		t.Fatalf("expected first ID to be F-CI, got %s", loaded.Entries[0].ID)
	}
	if loaded.Entries[1].Fingerprint != fpAAA {
		t.Fatalf("expected second fingerprint to be %s, got %s", fpAAA, loaded.Entries[1].Fingerprint)
	}
	if loaded.Entries[2].Fingerprint != fpBBB {
		t.Fatalf("expected third fingerprint to be %s, got %s", fpBBB, loaded.Entries[2].Fingerprint)
	}
}

func TestBaselinePrune(t *testing.T) {
	now := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	past := now.Add(-24 * time.Hour)
	future := now.Add(24 * time.Hour)

	b := &Baseline{
		SchemaVersion: SchemaVersion,
		Entries: []Entry{
			{ID: "F-EXPIRED", Reason: "old", CreatedAt: now, ExpiresAt: &past},
			{ID: "F-ACTIVE", Reason: "current", CreatedAt: now, ExpiresAt: &future},
			{ID: "F-NO-EXPIRY", Reason: "forever", CreatedAt: now},
		},
	}

	pruned := b.Prune(now)
	if pruned != 1 {
		t.Fatalf("expected to prune 1 entry, pruned %d", pruned)
	}
	if len(b.Entries) != 2 {
		t.Fatalf("expected 2 remaining entries, got %d", len(b.Entries))
	}
	for _, e := range b.Entries {
		if e.ID == "F-EXPIRED" {
			t.Fatal("expired entry should have been pruned")
		}
	}
}

func TestBaselinePruneKeepsNonExpiredFingerprint(t *testing.T) {
	now := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC)
	future := now.Add(24 * time.Hour)
	fp := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	b := &Baseline{
		SchemaVersion: SchemaVersion,
		Entries: []Entry{
			{ID: "F-ENV-001", Fingerprint: fp, Reason: "current", CreatedAt: now, ExpiresAt: &future},
		},
	}

	pruned := b.Prune(now)
	if pruned != 0 {
		t.Fatalf("expected 0 pruned, got %d", pruned)
	}
	if len(b.Entries) != 1 {
		t.Fatalf("expected entry to remain, got %d", len(b.Entries))
	}
}

func TestBaselineAddRejectsInvalidFingerprint(t *testing.T) {
	b := &Baseline{SchemaVersion: SchemaVersion}
	entry := Entry{
		ID:          "F-ENV-001",
		Reason:      "reason",
		Fingerprint: "invalid-fp",
	}
	_, err := b.Add(entry)
	if err == nil {
		t.Fatal("expected error when adding invalid fingerprint")
	}
}

func TestBaselineAddUpdatesSameIDAndFingerprint(t *testing.T) {
	b := &Baseline{SchemaVersion: SchemaVersion}
	fp := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	e1 := Entry{ID: "F-ENV-001", Fingerprint: fp, Reason: "first", CreatedAt: time.Now()}
	e2 := Entry{ID: "F-ENV-001", Fingerprint: fp, Reason: "updated", CreatedAt: time.Now()}

	updated, err := b.Add(e1)
	if err != nil || updated {
		t.Fatalf("first add: updated=%v, err=%v", updated, err)
	}

	updated, err = b.Add(e2)
	if err != nil || !updated {
		t.Fatalf("second add: updated=%v, err=%v", updated, err)
	}

	if len(b.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(b.Entries))
	}
	if b.Entries[0].Reason != "updated" {
		t.Fatalf("expected reason to be updated, got %q", b.Entries[0].Reason)
	}
}

func TestBaselineAddDoesNotMergeSameIDWithDifferentFingerprint(t *testing.T) {
	b := &Baseline{SchemaVersion: SchemaVersion}
	fp1 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	fp2 := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b856"
	e1 := Entry{ID: "F-ENV-001", Fingerprint: fp1, Reason: "first", CreatedAt: time.Now()}
	e2 := Entry{ID: "F-ENV-001", Fingerprint: fp2, Reason: "second", CreatedAt: time.Now()}

	_, err := b.Add(e1)
	if err != nil {
		t.Fatalf("add e1: %v", err)
	}
	_, err = b.Add(e2)
	if err != nil {
		t.Fatalf("add e2: %v", err)
	}

	if len(b.Entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(b.Entries))
	}
}

func TestBaselineRemoveWithEmptyFingerprintRemovesOnlyIDOnlyEntry(t *testing.T) {
	fp := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	b := &Baseline{
		SchemaVersion: SchemaVersion,
		Entries: []Entry{
			{ID: "F-ENV-001", Fingerprint: "", Reason: "broad"},
			{ID: "F-ENV-001", Fingerprint: fp, Reason: "specific"},
		},
	}

	removed := b.Remove("F-ENV-001", "")
	if !removed {
		t.Fatal("expected ID-only entry to be removed")
	}
	if len(b.Entries) != 1 {
		t.Fatalf("expected 1 remaining entry, got %d", len(b.Entries))
	}
	if b.Entries[0].Fingerprint != fp {
		t.Fatalf("expected fingerprint entry to remain, got ID %s with fingerprint %q", b.Entries[0].ID, b.Entries[0].Fingerprint)
	}
}

func TestBaselineRemoveWithFingerprintRemovesOnlyExactFingerprintEntry(t *testing.T) {
	fp := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	b := &Baseline{
		SchemaVersion: SchemaVersion,
		Entries: []Entry{
			{ID: "F-ENV-001", Fingerprint: "", Reason: "broad"},
			{ID: "F-ENV-001", Fingerprint: fp, Reason: "specific"},
		},
	}

	removed := b.Remove("F-ENV-001", fp)
	if !removed {
		t.Fatal("expected fingerprint entry to be removed")
	}
	if len(b.Entries) != 1 {
		t.Fatalf("expected 1 remaining entry, got %d", len(b.Entries))
	}
	if b.Entries[0].Fingerprint != "" {
		t.Fatalf("expected ID-only entry to remain, got ID %s with fingerprint %q", b.Entries[0].ID, b.Entries[0].Fingerprint)
	}
}
