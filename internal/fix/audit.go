package fix

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

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
// relative to the current working directory.
func DefaultAuditLog() *AuditLog {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	return NewAuditLog(filepath.Join(cwd, ".devdiag", "audit", "audit.ndjson"))
}

// Write appends a single audit entry.
func (a *AuditLog) Write(entry schema.FixAuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(a.path), 0755); err != nil {
		return fmt.Errorf("create audit dir: %w", err)
	}

	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer f.Close()

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
	return nil
}
