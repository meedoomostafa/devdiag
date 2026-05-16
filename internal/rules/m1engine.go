package rules

import (
	"fmt"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/graph"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// M1Engine is the Milestone 1 Go rule engine behind the PolicyEngine interface.
type M1Engine struct{}

// NewM1Engine creates the M1 rule engine.
func NewM1Engine() *M1Engine {
	return &M1Engine{}
}

// Evaluate converts collector evidence into findings.
func (e *M1Engine) Evaluate(snapshot graph.NormalizedSnapshot) ([]schema.Finding, error) {
	var findings []schema.Finding

	for _, c := range snapshot.Collectors {
		switch c.Name {
		case "env":
			findings = append(findings, e.envRules(c)...)
		case "compose":
			findings = append(findings, e.composeRules(c)...)
		case "git":
			findings = append(findings, e.gitRules(c)...)
		case "repo":
			findings = append(findings, e.repoRules(c)...)
		case "runtime":
			findings = append(findings, e.runtimeRules(c)...)
		case "ci":
			findings = append(findings, e.ciRules(c)...)
		case "self":
			// self collector produces no findings in M1
		}
	}

	return findings, nil
}

// envRules creates findings from env collector evidence.
func (e *M1Engine) envRules(result schema.CollectorResult) []schema.Finding {
	var findings []schema.Finding
	var envMissing, envExampleKeys []string

	for _, ev := range result.Evidence {
		switch ev.Source {
		case ".env":
			if ev.Value == "missing" {
				envMissing = append(envMissing, ev.Value)
			}
		case ".env.example":
			if strings.HasPrefix(ev.Value, "keys: ") {
				envExampleKeys = strings.Split(strings.TrimPrefix(ev.Value, "keys: "), ", ")
			}
		case "missing_keys":
			// keys present in .env.example but not in .env
			missing := strings.Split(ev.Value, ", ")
			findings = append(findings, schema.Finding{
				ID:           "F-ENV-001",
				Title:        fmt.Sprintf("Missing env keys from .env: %s", strings.Join(missing, ", ")),
				Severity:     schema.SeverityMedium,
				Confidence:   0.7,
				Symptom:      "Keys defined in .env.example are not present in .env",
				Evidence:     []schema.Evidence{ev},
				LikelyCauses: []string{".env file not created from .env.example"},
			})
		}
	}

	// Missing .env file entirely
	if len(envMissing) > 0 && len(envExampleKeys) > 0 {
		findings = append(findings, schema.Finding{
			ID:           "F-ENV-001",
			Title:        ".env.example exists but no local .env was found",
			Severity:     schema.SeverityMedium,
			Confidence:   0.5,
			Symptom:      ".env.example exists but .env is missing",
			Evidence:     result.Evidence,
			LikelyCauses: []string{"Project may require local env vars but .env is not present"},
		})
	}

	return findings
}

// composeRules creates findings from compose collector evidence.
func (e *M1Engine) composeRules(result schema.CollectorResult) []schema.Finding {
	var findings []schema.Finding
	for _, ev := range result.Evidence {
		findings = append(findings, schema.Finding{
			ID:           "F-ENV-002",
			Title:        "Compose references env variable that may be undefined",
			Severity:     schema.SeverityMedium,
			Confidence:   0.6,
			Symptom:      "Compose file references an environment variable that may not be defined",
			Evidence:     []schema.Evidence{ev},
			LikelyCauses: []string{"Variable may be missing from .env or host environment"},
		})
	}
	return findings
}

// gitRules creates findings from git collector evidence.
func (e *M1Engine) gitRules(result schema.CollectorResult) []schema.Finding {
	var findings []schema.Finding
	var trackedEnv []string
	var envIgnored, envExists bool

	for _, ev := range result.Evidence {
		switch ev.Source {
		case "git_tracked_env":
			trackedEnv = strings.Split(ev.Value, ", ")
		case "git_env_ignored":
			envIgnored = ev.Value == "true"
		case "git_env_exists":
			envExists = ev.Value == "true"
		}
	}

	if len(trackedEnv) > 0 {
		findings = append(findings, schema.Finding{
			ID:           "F-GIT-001",
			Title:        fmt.Sprintf("Env file tracked by Git: %s", strings.Join(trackedEnv, ", ")),
			Severity:     schema.SeverityMedium,
			Confidence:   0.9,
			Symptom:      "Environment files containing secrets are tracked in version control",
			Evidence:     result.Evidence,
			LikelyCauses: []string{".env file was committed to Git before being added to .gitignore"},
		})
	}

	// Only emit F-GIT-002 if .env exists on disk AND is not ignored
	if envExists && !envIgnored {
		findings = append(findings, schema.Finding{
			ID:           "F-GIT-002",
			Title:        ".env exists but is not ignored by Git",
			Severity:     schema.SeverityMedium,
			Confidence:   0.7,
			Symptom:      ".env file is not ignored by Git and may be committed accidentally",
			Evidence:     result.Evidence,
			LikelyCauses: []string{"Missing .env entry in .gitignore or ignore pattern does not match"},
		})
	}

	return findings
}

// repoRules creates findings from repo collector evidence.
func (e *M1Engine) repoRules(result schema.CollectorResult) []schema.Finding {
	var findings []schema.Finding

	// Check for multiple lockfiles (package manager conflict)
	for _, ev := range result.Evidence {
		if ev.Source == "lockfiles" {
			lockfiles := strings.Split(ev.Value, ", ")
			if len(lockfiles) > 1 {
				findings = append(findings, schema.Finding{
					ID:         "F-PM-001",
					Title:      fmt.Sprintf("Multiple package manager lockfiles: %s", ev.Value),
					Severity:   schema.SeverityMedium,
					Confidence: 0.6,
					Symptom:    "Multiple lockfiles may indicate package manager conflict or migration",
					Evidence:   []schema.Evidence{ev},
					LikelyCauses: []string{
						"Migration between package managers",
						"Monorepo with different package managers",
					},
				})
			}
		}
	}

	return findings
}

// runtimeRules creates findings from runtime collector evidence.
func (e *M1Engine) runtimeRules(result schema.CollectorResult) []schema.Finding {
	var findings []schema.Finding
	var declarations []string

	for _, ev := range result.Evidence {
		declarations = append(declarations, ev.Value)
	}

	if len(declarations) > 0 {
		findings = append(findings, schema.Finding{
			ID:           "F-RUNTIME-DECL-001",
			Title:        "Runtime version declaration discovered",
			Severity:     schema.SeverityInfo,
			Confidence:   0.9,
			Symptom:      "Project declares expected runtime versions",
			Evidence:     result.Evidence,
			LikelyCauses: []string{"Version pinning helps reproducibility"},
		})
	}

	return findings
}

// ciRules creates findings from ci collector evidence.
func (e *M1Engine) ciRules(result schema.CollectorResult) []schema.Finding {
	// M1: extract evidence only, no high-confidence mismatches yet
	return nil
}
