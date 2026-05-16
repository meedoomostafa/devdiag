package redact

import (
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Engine applies redaction rules to strings and reports.
type Engine struct {
	Level Level
}

// NewEngine creates a redaction engine with the given level.
func NewEngine(level Level) *Engine {
	return &Engine{Level: level}
}

// RedactString applies redaction rules to a single string value.
func (e *Engine) RedactString(input string, sourceType string) string {
	if e.Level == LevelOff {
		return input
	}

	result := input
	result = redactEnvValues(result)
	result = redactCLISecrets(result)
	result = redactURL(result)
	result = redactJWT(result)
	result = redactHome(result)

	if e.Level == LevelStrict {
		result = redactStrictTokens(result)
	}

	return result
}

// RedactReport returns a deep-redacted copy of the report.
// It always returns a distinct pointer, even when redaction is off.
func (e *Engine) RedactReport(r *schema.Report) *schema.Report {
	if r == nil {
		return nil
	}

	redacted := *r
	redacted.RedactionStatus = string(e.Level)

	if e.Level == LevelOff {
		return &redacted
	}

	redacted.Findings = make([]schema.Finding, len(r.Findings))
	for i, f := range r.Findings {
		redacted.Findings[i] = e.redactFinding(f)
	}
	redacted.Collectors = make([]schema.CollectorResult, len(r.Collectors))
	for i, c := range r.Collectors {
		redacted.Collectors[i] = e.redactCollector(c)
	}
	// Redact top-level repo/host fields that contain paths
	redacted.Repo.Root = e.RedactString(r.Repo.Root, "repo_root")
	redacted.Host.OS = e.RedactString(r.Host.OS, "host_os")
	redacted.Host.Distro = e.RedactString(r.Host.Distro, "host_distro")
	redacted.Host.Version = e.RedactString(r.Host.Version, "host_version")
	redacted.Host.Kernel = e.RedactString(r.Host.Kernel, "host_kernel")
	redacted.Host.Arch = e.RedactString(r.Host.Arch, "host_arch")
	redacted.Host.Session = e.RedactString(r.Host.Session, "host_session")
	return &redacted
}

func (e *Engine) redactFinding(f schema.Finding) schema.Finding {
	redacted := f
	redacted.Title = e.RedactString(f.Title, "finding_title")
	redacted.Symptom = e.RedactString(f.Symptom, "symptom")
	redacted.Evidence = make([]schema.Evidence, len(f.Evidence))
	for j, ev := range f.Evidence {
		redacted.Evidence[j] = schema.Evidence{
			Source: ev.Source,
			Value:  e.RedactString(ev.Value, "evidence_value"),
		}
	}
	redacted.LikelyCauses = make([]string, len(f.LikelyCauses))
	for j, c := range f.LikelyCauses {
		redacted.LikelyCauses[j] = e.RedactString(c, "likely_cause")
	}
	redacted.Fixes = make([]schema.Fix, len(f.Fixes))
	for j, fix := range f.Fixes {
		redacted.Fixes[j] = e.redactFix(fix)
	}
	return redacted
}

func (e *Engine) redactCollector(c schema.CollectorResult) schema.CollectorResult {
	redacted := c
	redacted.Evidence = make([]schema.Evidence, len(c.Evidence))
	for j, ev := range c.Evidence {
		redacted.Evidence[j] = schema.Evidence{
			Source: ev.Source,
			Value:  e.RedactString(ev.Value, "collector_evidence"),
		}
	}
	redacted.Notes = make([]string, len(c.Notes))
	for j, n := range c.Notes {
		redacted.Notes[j] = e.RedactString(n, "collector_note")
	}
	return redacted
}

func (e *Engine) redactFix(fix schema.Fix) schema.Fix {
	redacted := fix
	redacted.Title = e.RedactString(fix.Title, "fix_title")
	redacted.Commands = make([]string, len(fix.Commands))
	for j, cmd := range fix.Commands {
		redacted.Commands[j] = e.RedactString(cmd, "fix_command")
	}
	redacted.Rollback = make([]string, len(fix.Rollback))
	for j, r := range fix.Rollback {
		redacted.Rollback[j] = e.RedactString(r, "fix_rollback")
	}
	return redacted
}
