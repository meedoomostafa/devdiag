package capsule

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// InspectResult is the parsed metadata from a capsule.
type InspectResult struct {
	Manifest *Manifest
	FileList []string
	Valid    bool
	Errors   []string
}

// Inspect reads a capsule .tgz and returns metadata without extracting raw logs.
func Inspect(path string) (*InspectResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open capsule: %w", err)
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("read gzip: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	return inspectTar(tr)
}

// InspectFromBytes inspects a capsule from an in-memory byte slice.
func InspectFromBytes(data []byte) (*InspectResult, error) {
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("read gzip: %w", err)
	}
	defer gr.Close()

	tr := tar.NewReader(gr)
	return inspectTar(tr)
}

func inspectTar(tr *tar.Reader) (*InspectResult, error) {
	result := &InspectResult{Valid: true}

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("tar read error: %v", err))
			break
		}

		if !isSafePath(header.Name) {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("unsafe path rejected: %s", header.Name))
			continue
		}

		result.FileList = append(result.FileList, header.Name)

		if header.Name == "manifest.json" {
			data, err := io.ReadAll(tr)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("read manifest: %v", err))
				continue
			}
			var m Manifest
			if err := json.Unmarshal(data, &m); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("parse manifest: %v", err))
			} else {
				result.Manifest = &m
			}
		}
	}

	if result.Manifest == nil {
		result.Valid = false
		result.Errors = append(result.Errors, "missing manifest.json")
	}

	return result, nil
}

// Summary returns a human-readable capsule summary (no raw logs).
func (r *InspectResult) Summary() string {
	var b strings.Builder
	if r.Manifest != nil {
		m := r.Manifest
		fmt.Fprintf(&b, "Capsule: run_id=%s devdiag=%s schema=%s\n", m.RunID, m.DevDiagVersion, m.CapsuleSchemaVersion)
		fmt.Fprintf(&b, "Created: %s\n", m.CreatedAt)
		fmt.Fprintf(&b, "Redaction: %s\n", m.RedactionStatus)
		fmt.Fprintf(&b, "Files (%d):\n", len(m.Files))
		for _, f := range m.Files {
			fmt.Fprintf(&b, "  %s (%d bytes)\n", f.Path, f.SizeBytes)
		}
	} else {
		fmt.Fprintln(&b, "Capsule: manifest not found")
	}
	if len(r.Errors) > 0 {
		fmt.Fprintln(&b, "Errors:")
		for _, e := range r.Errors {
			fmt.Fprintf(&b, "  - %s\n", e)
		}
	}
	return b.String()
}
