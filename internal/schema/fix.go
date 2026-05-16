package schema

// FixClass describes the safety level of a proposed fix.
type FixClass string

const (
	FixSafe    FixClass = "safe"
	FixGuarded FixClass = "guarded"
	FixManual  FixClass = "manual"
	FixBlocked FixClass = "blocked"
)

// Fix represents a single remediation option.
type Fix struct {
	Class    FixClass `json:"class"`
	Title    string   `json:"title"`
	Commands []string `json:"commands,omitempty"`
	Rollback []string `json:"rollback,omitempty"`
}
