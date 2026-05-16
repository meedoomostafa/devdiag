package capsule

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/meedoomostafa/devdiag/internal/repro"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Builder creates a redacted support capsule as a local .tgz.
type Builder struct {
	RedactionStatus string
	DevDiagVersion  string
	TraceArtifact   []byte // optional redacted trace result JSON
}

// NewBuilder creates a capsule builder.
func NewBuilder(redactionStatus, version string) *Builder {
	return &Builder{
		RedactionStatus: redactionStatus,
		DevDiagVersion:  version,
	}
}

// SetTraceArtifact attaches a redacted trace result to the capsule.
func (b *Builder) SetTraceArtifact(data []byte) {
	b.TraceArtifact = data
}

// Build creates a .tgz capsule from report and repro artifacts.
func (b *Builder) Build(w io.Writer, report *schema.Report, reproResult *repro.ReproResult) error {
	gw := gzip.NewWriter(w)
	defer gw.Close()
	tw := tar.NewWriter(gw)
	defer tw.Close()

	now := time.Now()
	manifest := &Manifest{
		CapsuleSchemaVersion: "0.1",
		DevDiagVersion:       b.DevDiagVersion,
		RunID:                report.RunID,
		CreatedAt:            now.Format(time.RFC3339),
		RedactionStatus:      b.RedactionStatus,
		Files:                []ManifestFile{},
	}

	// Write report as JSON
	reportData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	if err := b.addFile(tw, manifest, "report.json", reportData, now); err != nil {
		return err
	}

	// Write findings as JSON
	findingsData, err := json.MarshalIndent(report.Findings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal findings: %w", err)
	}
	if err := b.addFile(tw, manifest, "findings.json", findingsData, now); err != nil {
		return err
	}

	// Write repro result if present
	if reproResult != nil {
		reproData, err := json.MarshalIndent(reproResult, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal repro: %w", err)
		}
		if err := b.addFile(tw, manifest, "repro.json", reproData, now); err != nil {
			return err
		}
	}

	// Ensure snapshot directory exists in tar before files
	if len(report.Collectors) > 0 || b.TraceArtifact != nil {
		if err := b.addDir(tw, "snapshot/", now); err != nil {
			return err
		}
	}
	// Write collector snapshots (only available ones)
	for _, c := range report.Collectors {
		cData, err := json.MarshalIndent(c, "", "  ")
		if err != nil {
			manifest.Notes = append(manifest.Notes, fmt.Sprintf("marshal failed for collector %s: %v", c.Name, err))
			continue
		}
		name := fmt.Sprintf("snapshot/%s.json", c.Name)
		if err := b.addFile(tw, manifest, name, cData, now); err != nil {
			return err
		}
	}

	// Write trace artifact if present (overrides or supplements snapshot/trace.json)
	if b.TraceArtifact != nil {
		if err := b.addFile(tw, manifest, "snapshot/trace.json", b.TraceArtifact, now); err != nil {
			manifest.Notes = append(manifest.Notes, fmt.Sprintf("trace artifact add failed: %v", err))
			// non-fatal: continue building capsule
		}
	}

	// Write manifest last so we have all file checksums
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	if err := b.addFile(tw, manifest, "manifest.json", manifestData, now); err != nil {
		return err
	}

	return nil
}

func (b *Builder) addFile(tw *tar.Writer, manifest *Manifest, name string, data []byte, modTime time.Time) error {
	if !isSafePath(name) {
		return fmt.Errorf("unsafe capsule path: %s", name)
	}

	sum := sha256.Sum256(data)
	checksum := fmt.Sprintf("%x", sum)

	header := &tar.Header{
		Name:    name,
		Mode:    0644,
		Size:    int64(len(data)),
		ModTime: modTime,
	}
	if err := tw.WriteHeader(header); err != nil {
		return err
	}
	if _, err := tw.Write(data); err != nil {
		return err
	}

	manifest.Files = append(manifest.Files, ManifestFile{
		Path:      name,
		SizeBytes: len(data),
		SHA256:    checksum,
	})
	return nil
}

func (b *Builder) addDir(tw *tar.Writer, name string, modTime time.Time) error {
	if !isSafePath(name) {
		return fmt.Errorf("unsafe capsule path: %s", name)
	}
	header := &tar.Header{
		Name:     name,
		Mode:     0755,
		Typeflag: tar.TypeDir,
		ModTime:  modTime,
	}
	return tw.WriteHeader(header)
}

func isSafePath(p string) bool {
	p = filepath.Clean(p)
	if filepath.IsAbs(p) {
		return false
	}
	// Check each path component for traversal, not substring match
	for _, part := range strings.Split(p, string(filepath.Separator)) {
		if part == ".." {
			return false
		}
	}
	if strings.HasPrefix(p, "/") {
		return false
	}
	return true
}

// Manifest describes a capsule archive.
type Manifest struct {
	CapsuleSchemaVersion string         `json:"capsule_schema_version"`
	DevDiagVersion       string         `json:"devdiag_version"`
	RunID                string         `json:"run_id"`
	CreatedAt            string         `json:"created_at"`
	RedactionStatus      string         `json:"redaction_status"`
	Files                []ManifestFile `json:"files"`
	Notes                []string       `json:"notes,omitempty"`
}

// ManifestFile is a single entry in the capsule manifest.
type ManifestFile struct {
	Path      string `json:"path"`
	SizeBytes int    `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}
