package trace

import (
	"fmt"
	"strings"
	"time"
)

// Scope defines which syscall categories to trace.
type Scope string

const (
	ScopeFile    Scope = "file"
	ScopeProcess Scope = "process"
	ScopeNetwork Scope = "network"
)

// ParseScopes parses a comma-separated list of scope names.
func ParseScopes(s string) ([]Scope, error) {
	if s == "" {
		return nil, fmt.Errorf("scope string is empty")
	}
	parts := strings.Split(s, ",")
	var scopes []Scope
	for _, p := range parts {
		p = strings.TrimSpace(strings.ToLower(p))
		if p == "" {
			continue
		}
		switch p {
		case string(ScopeFile):
			scopes = append(scopes, ScopeFile)
		case string(ScopeProcess):
			scopes = append(scopes, ScopeProcess)
		case string(ScopeNetwork):
			scopes = append(scopes, ScopeNetwork)
		default:
			return nil, fmt.Errorf("invalid scope: %q", p)
		}
	}
	if len(scopes) == 0 {
		return nil, fmt.Errorf("no valid scopes found")
	}
	return scopes, nil
}

// Event is a single parsed strace line.
type Event struct {
	Timestamp time.Time     `json:"timestamp,omitempty"`
	PID       int           `json:"pid"`
	Syscall   string        `json:"syscall"`
	Args      []string      `json:"args,omitempty"`
	Result    string        `json:"result"`
	Error     string        `json:"error,omitempty"`
	Duration  time.Duration `json:"duration,omitempty"`
}

// Result is the output of a trace run.
type Result struct {
	Command          string        `json:"command"`
	Args             []string      `json:"args"`
	Scopes           []Scope       `json:"scopes"`
	Events           []Event       `json:"events"`
	TimedOut         bool          `json:"timed_out"`
	Partial          bool          `json:"partial"`
	TraceUnavailable bool          `json:"trace_unavailable"`
	ProcessFailed    bool          `json:"process_failed"`
	Canceled         bool          `json:"canceled"`
	ExitCode         int           `json:"exit_code"`
	Duration         time.Duration `json:"duration"`
	Notes            []string      `json:"notes,omitempty"`
}
