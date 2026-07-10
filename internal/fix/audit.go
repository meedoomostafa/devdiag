package fix

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/meedoomostafa/devdiag/internal/artifact"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// AuditLog writes append-only JSON lines for fix actions.
type AuditLog struct {
	path string
	mu   sync.Mutex
}

// NewAuditLog creates an audit log at the given path.
func NewAuditLog(path string) *AuditLog {
	return &AuditLog{path: path}
}

// DefaultAuditLog returns an audit log at .devdiag/audit/audit.ndjson
// relative to the discovered repository root.
func DefaultAuditLog() *AuditLog {
	base, err := artifact.DiscoverBase(".")
	if err != nil {
		base = "."
	}
	return NewAuditLog(filepath.Join(base, ".devdiag", "audit", "audit.ndjson"))
}

// Write appends a single audit entry.
func (a *AuditLog) Write(entry schema.FixAuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	dir := filepath.Dir(a.path)
	if err := os.MkdirAll(dir, artifact.DirPerm); err != nil {
		return fmt.Errorf("create audit dir: %w", err)
	}
	// Force owner-only on directory in case it already existed
	_ = os.Chmod(dir, artifact.DirPerm)

	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, artifact.FilePerm)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

	// Ensure owner-only permissions on the file
	_ = os.Chmod(a.path, artifact.FilePerm)

	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal audit entry: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write audit entry: %w", err)
	}
	if _, err := f.WriteString("\n"); err != nil {
		return fmt.Errorf("write newline: %w", err)
	}
	// Fsync so an applied mutation cannot survive a crash that its audit
	// entry does not.
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync audit log: %w", err)
	}
	return nil
}
