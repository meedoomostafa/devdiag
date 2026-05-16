package classifier

import (
	"strings"

	"github.com/meedoomostafa/devdiag/internal/repro"
)

// Rule is a single classification pattern.
type Rule struct {
	ID            string
	Kind          string
	Patterns      []string
	SourceStream  string // "stdout", "stderr", or "any"
	Confidence    float64
	CaseSensitive bool
}

// DefaultRules is the built-in classifier rule set.
var DefaultRules = []Rule{
	{
		ID:           "perm-denied-001",
		Kind:         "permission_denied",
		Patterns:     []string{"permission denied", "EACCES", "Operation not permitted"},
		SourceStream: "any",
		Confidence:   0.7,
	},
	{
		ID:           "missing-file-001",
		Kind:         "missing_file",
		Patterns:     []string{"No such file or directory", "ENOENT", "command not found"},
		SourceStream: "any",
		Confidence:   0.7,
	},
	{
		ID:           "addr-in-use-001",
		Kind:         "address_in_use",
		Patterns:     []string{"address already in use", "EADDRINUSE", "bind: Address already in use"},
		SourceStream: "any",
		Confidence:   0.9,
	},
	{
		ID:           "conn-refused-001",
		Kind:         "connection_refused",
		Patterns:     []string{"connection refused", "ECONNREFUSED", "Connection refused"},
		SourceStream: "any",
		Confidence:   0.7,
	},
	{
		ID:           "dep-fail-001",
		Kind:         "dependency_failure",
		Patterns:     []string{"npm ERR!", "pip failed", "go: module", "unresolved import", "cannot resolve"},
		SourceStream: "any",
		Confidence:   0.6,
	},
	{
		ID:           "compose-config-001",
		Kind:         "compose_config_error",
		Patterns:     []string{"interpolation", "Invalid interpolation", "compose config", "docker compose config"},
		SourceStream: "any",
		Confidence:   0.6,
	},
}

// Classifier scans repro output and returns matched classifications.
type Classifier struct {
	rules []Rule
}

// New creates a Classifier with the default rule set.
func New() *Classifier {
	return &Classifier{rules: DefaultRules}
}

// Classify scans stdout and stderr and returns matched classifications.
func (c *Classifier) Classify(stdout, stderr string) []repro.Classification {
	var results []repro.Classification

	for _, rule := range c.rules {
		var matched bool
		var text string

		switch rule.SourceStream {
		case "stdout":
			text = stdout
		case "stderr":
			text = stderr
		default:
			text = stdout + "\n" + stderr
		}

		for _, pat := range rule.Patterns {
			if rule.CaseSensitive {
				if strings.Contains(text, pat) {
					matched = true
					break
				}
			} else {
				if strings.Contains(strings.ToLower(text), strings.ToLower(pat)) {
					matched = true
					break
				}
			}
		}

		if matched {
			excerpt := extractExcerpt(text, rule.Patterns, 120)
			results = append(results, repro.Classification{
				Kind:         rule.Kind,
				SourceStream: rule.SourceStream,
				Confidence:   rule.Confidence,
				PatternID:    rule.ID,
				Excerpt:      excerpt,
			})
		}
	}

	return results
}

func extractExcerpt(text string, patterns []string, maxLen int) string {
	lines := strings.Split(text, "\n")
	for _, line := range lines {
		for _, pat := range patterns {
			if strings.Contains(strings.ToLower(line), strings.ToLower(pat)) {
				if len(line) > maxLen {
					line = line[:maxLen] + "..."
				}
				return strings.TrimSpace(line)
			}
		}
	}
	return ""
}
