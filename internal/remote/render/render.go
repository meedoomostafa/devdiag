package render

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/remote/target"
	"github.com/meedoomostafa/devdiag/internal/version"
)

// RemoteResult is the top-level output for remote commands.
type RemoteResult struct {
	SchemaVersion      string        `json:"schema_version"`
	DevDiagVersion     string        `json:"devdiag_version"`
	Target             target.Target `json:"target"`
	Status             string        `json:"status"`
	Profile            string        `json:"profile,omitempty"`
	SessionID          string        `json:"session_id,omitempty"`
	RemoteDir          string        `json:"remote_dir,omitempty"`
	FilesWritten       int           `json:"files_written,omitempty"`
	FilesCreated       []string      `json:"files_created,omitempty"`
	NoDotfilesModified bool          `json:"no_dotfiles_modified,omitempty"`
	CleanupCommand     string        `json:"cleanup_command,omitempty"`
	EnterCommand       string        `json:"enter_command,omitempty"`
	Findings           []Finding     `json:"findings,omitempty"`
	Notes              []string      `json:"notes,omitempty"`
	RedactionStatus    string        `json:"redaction_status"`
}

// Finding represents a remote diagnostic finding.
type Finding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// Render renders a RemoteResult in the specified format.
func Render(r *RemoteResult, format string, w io.Writer) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "ndjson":
		// Emit a single NDJSON event line for the result.
		return json.NewEncoder(w).Encode(r)
	default:
		return renderHuman(r, w)
	}
}

func renderHuman(r *RemoteResult, w io.Writer) error {
	var b strings.Builder

	switch r.Status {
	case "ok", "synced":
		b.WriteString("DevDiag remote sync completed\n")
	case "doctor":
		b.WriteString("DevDiag remote doctor\n")
	case "cleaned":
		b.WriteString("DevDiag remote clean completed\n")
	default:
		b.WriteString(fmt.Sprintf("DevDiag remote operation: %s\n", r.Status))
	}

	if r.Target.Raw != "" {
		b.WriteString(fmt.Sprintf("Target: %s\n", r.Target.String()))
	}
	if r.Profile != "" {
		b.WriteString(fmt.Sprintf("Profile: %s\n", r.Profile))
	}
	if r.SessionID != "" {
		b.WriteString(fmt.Sprintf("Session: %s\n", r.SessionID))
	}
	if r.RemoteDir != "" {
		b.WriteString(fmt.Sprintf("Remote dir: %s\n", r.RemoteDir))
	}

	if len(r.FilesCreated) > 0 {
		b.WriteString("\nChanged files\n")
		for _, f := range r.FilesCreated {
			b.WriteString(fmt.Sprintf("  created  %s\n", f))
		}
	}

	if r.NoDotfilesModified {
		b.WriteString("\nNo existing dotfiles were modified.\n")
	}

	if r.CleanupCommand != "" {
		b.WriteString("\nCleanup\n")
		b.WriteString(fmt.Sprintf("  %s\n", r.CleanupCommand))
	}

	if len(r.Findings) > 0 {
		b.WriteString("\nFindings\n")
		for _, f := range r.Findings {
			b.WriteString(fmt.Sprintf("  [%s] %s: %s\n", f.Severity, f.ID, f.Title))
		}
	}

	if len(r.Notes) > 0 {
		b.WriteString("\nNotes\n")
		for _, n := range r.Notes {
			b.WriteString(fmt.Sprintf("  %s\n", n))
		}
	}

	_, err := w.Write([]byte(b.String()))
	return err
}

// NewSyncResult constructs a standard RemoteResult for a successful sync.
func NewSyncResult(t *target.Target, profile, sessionID, remoteDir string, files []string) *RemoteResult {
	return &RemoteResult{
		SchemaVersion:      "0.1",
		DevDiagVersion:     version.Version,
		Target:             *t,
		Status:             "synced",
		Profile:            profile,
		SessionID:          sessionID,
		RemoteDir:          remoteDir,
		FilesWritten:       len(files),
		FilesCreated:       files,
		NoDotfilesModified: true,
		CleanupCommand:     fmt.Sprintf("devdiag remote clean %s --session %s", t.String(), sessionID),
	}
}

// NewDoctorResult constructs a standard RemoteResult for doctor.
func NewDoctorResult(t *target.Target) *RemoteResult {
	return &RemoteResult{
		SchemaVersion:   "0.1",
		DevDiagVersion:  version.Version,
		Target:          *t,
		Status:          "doctor",
		RedactionStatus: "default",
	}
}
