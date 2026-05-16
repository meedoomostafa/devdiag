package schema

// RepoInfo holds minimal repo metadata.
type RepoInfo struct {
	Root    string   `json:"root"`
	Signals []string `json:"signals,omitempty"`
}

// HostInfo holds minimal host metadata.
type HostInfo struct {
	OS      string `json:"os"`
	Distro  string `json:"distro,omitempty"`
	Version string `json:"version,omitempty"`
	Kernel  string `json:"kernel,omitempty"`
	Session string `json:"session,omitempty"`
}

// Report is the top-level output container.
// All required fields must be present even in an empty/stub scan.
type Report struct {
	SchemaVersion   string            `json:"schema_version"`
	DevDiagVersion  string            `json:"devdiag_version"`
	RunID           string            `json:"run_id"`
	RedactionStatus string            `json:"redaction_status"`
	Repo            RepoInfo          `json:"repo"`
	Host            HostInfo          `json:"host"`
	Collectors      []CollectorResult `json:"collectors"`
	Findings        []Finding         `json:"findings"`
}
