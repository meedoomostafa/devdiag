package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/meedoomostafa/devdiag/internal/remote/target"
)

var sessionIDRe = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z_[A-Za-z0-9][A-Za-z0-9_-]{5,63}$`)

// ValidateSessionID ensures a session ID matches the expected format.
func ValidateSessionID(id string) error {
	if !sessionIDRe.MatchString(id) {
		return fmt.Errorf("invalid session ID format: %q", id)
	}
	return nil
}

// ValidateManifest checks that a manifest is consistent and safe.
func ValidateManifest(m *Manifest) error {
	if err := ValidateManifestIdentity(m); err != nil {
		return err
	}
	if err := ValidateRootDir(m.RootDir, m.Target.Kind); err != nil {
		return fmt.Errorf("invalid root dir in manifest: %w", err)
	}
	for _, f := range m.Files {
		if err := ValidateManagedPath(m.RootDir, f.Path); err != nil {
			return fmt.Errorf("invalid managed path %q in manifest: %w", f.Path, err)
		}
	}

	return nil
}

// ValidateManifestIdentity checks cache lookup fields without validating cleanup
// paths. Explicit cleanup commands must be able to load unsafe manifests so the
// safety checks can refuse them with the documented exit code.
func ValidateManifestIdentity(m *Manifest) error {
	if m == nil {
		return fmt.Errorf("manifest must not be nil")
	}
	if m.SchemaVersion != "0.1" {
		return fmt.Errorf("unsupported manifest schema version: %q", m.SchemaVersion)
	}
	if err := ValidateSessionID(m.SessionID); err != nil {
		return err
	}
	if m.Target.Raw == "" {
		return fmt.Errorf("manifest target must not be empty")
	}
	switch m.Target.Kind {
	case target.KindSSH, target.KindContainer, target.KindK8s:
		// OK
	default:
		return fmt.Errorf("unsupported target kind %q", m.Target.Kind)
	}

	switch m.Status {
	case "active", "cleaned", "partial", "failed", "":
		// OK
	default:
		return fmt.Errorf("unsupported status %q", m.Status)
	}

	return nil
}

// GenerateID creates a unique session identifier.
func GenerateID() string {
	ts := time.Now().UTC().Format("20060102T150405Z")
	suffix := make([]byte, 3)
	if _, err := rand.Read(suffix); err != nil {
		return fmt.Sprintf("%s_%04x", ts, time.Now().UnixNano()%0xFFFF)
	}
	return fmt.Sprintf("%s_%s", ts, hex.EncodeToString(suffix))
}

// Manifest describes a single remote sync/enter session.
type Manifest struct {
	SchemaVersion  string        `json:"schema_version"`
	DevDiagVersion string        `json:"devdiag_version"`
	SessionID      string        `json:"session_id"`
	CreatedAt      string        `json:"created_at"`
	Target         target.Target `json:"target"`
	Profile        string        `json:"profile"`
	Mode           string        `json:"mode"` // temporary, persistent
	RootDir        string        `json:"root_dir"`
	Files          []ManagedFile `json:"files"`
	Backups        []BackupFile  `json:"backups"`
	Commands       []CommandLog  `json:"commands,omitempty"`
	Status         string        `json:"status"` // active, cleaned, partial, failed
	CleanupHints   []string      `json:"cleanup_hints,omitempty"`
}

// ManagedFile tracks a file created or modified by DevDiag.
type ManagedFile struct {
	Path       string `json:"path"`
	Mode       string `json:"mode"`
	Sha256     string `json:"sha256"`
	Created    bool   `json:"created"`
	Modified   bool   `json:"modified"`
	BackupPath string `json:"backup_path,omitempty"`
}

// BackupFile tracks a backup made before modification.
type BackupFile struct {
	OriginalPath string `json:"original_path"`
	BackupPath   string `json:"backup_path"`
	Sha256       string `json:"sha256"`
}

// CommandLog records a remote command executed.
type CommandLog struct {
	Name       string `json:"name"`
	Command    string `json:"command"`
	ExitCode   int    `json:"exit_code"`
	DurationMs int64  `json:"duration_ms"`
}

// SSHRootDir returns the default DevDiag remote root for SSH targets.
func SSHRootDir(sessionID string) string {
	return filepath.Join("~/.devdiag/remote", sessionID)
}

// ContainerRootDir returns the default DevDiag remote root for containers.
func ContainerRootDir(sessionID string) string {
	return filepath.Join("/tmp/devdiag-remote", sessionID)
}

// K8sRootDir returns the default DevDiag remote root for Kubernetes pods.
func K8sRootDir(sessionID string) string {
	return filepath.Join("/tmp/devdiag-remote", sessionID)
}

// ShellPath converts a validated generated remote path into a shell-friendly
// form. It preserves container paths and lets SSH "~/" paths expand through
// $HOME even when assigned to shell variables.
func ShellPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		return "$HOME/" + strings.TrimPrefix(path, "~/")
	}
	return path
}

// ShellQuote returns a POSIX single-quoted shell word.
func ShellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

// ValidateRootDir rejects obviously dangerous root directories.
func ValidateRootDir(dir string, kind target.Kind) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return fmt.Errorf("root dir is empty")
	}
	if !isSafeRemotePath(dir) {
		return fmt.Errorf("root dir contains unsafe characters")
	}
	if dir == "/" {
		return fmt.Errorf("root dir cannot be /")
	}
	if dir == "/home" {
		return fmt.Errorf("root dir cannot be /home")
	}
	if dir == "/tmp" {
		return fmt.Errorf("root dir cannot be /tmp")
	}
	cleanDir := filepath.Clean(dir)
	switch kind {
	case target.KindSSH:
		// For SSH, root must be a DevDiag-managed remote session.
		if !strings.HasPrefix(cleanDir, "~/.devdiag/remote/") && !strings.Contains(cleanDir, "/.devdiag/remote/") {
			return fmt.Errorf("ssh root dir must be within .devdiag/remote")
		}
	case target.KindContainer, target.KindK8s:
		if !strings.HasPrefix(cleanDir, "/tmp/devdiag-remote/") {
			return fmt.Errorf("%s root dir must be within /tmp/devdiag-remote", kind)
		}
	default:
		return fmt.Errorf("unsupported target kind %q", kind)
	}
	// Path traversal check
	if hasPathTraversal(dir) {
		return fmt.Errorf("root dir contains path traversal")
	}
	return nil
}

// ValidateManagedPath ensures path stays inside rootDir.
func ValidateManagedPath(rootDir string, path string) error {
	rootDir = strings.TrimSpace(rootDir)
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("path is empty")
	}
	if rootDir == "" {
		return fmt.Errorf("root dir is empty")
	}
	if !isSafeRemotePath(rootDir) || !isSafeRemotePath(path) {
		return fmt.Errorf("managed path contains unsafe characters")
	}
	if hasPathTraversal(path) {
		return fmt.Errorf("path contains path traversal")
	}
	cleanRoot := filepath.Clean(rootDir)
	cleanPath := filepath.Clean(path)
	if cleanPath == cleanRoot || !strings.HasPrefix(cleanPath, cleanRoot+"/") {
		return fmt.Errorf("managed path must be within the session root")
	}
	return nil
}

func isSafeRemotePath(path string) bool {
	for _, r := range path {
		if r >= 'a' && r <= 'z' {
			continue
		}
		if r >= 'A' && r <= 'Z' {
			continue
		}
		if r >= '0' && r <= '9' {
			continue
		}
		if strings.ContainsRune("._~/-", r) {
			continue
		}
		return false
	}
	return true
}

func hasPathTraversal(path string) bool {
	for _, part := range strings.Split(strings.ReplaceAll(path, "\\", "/"), "/") {
		if part == ".." {
			return true
		}
	}
	return false
}
