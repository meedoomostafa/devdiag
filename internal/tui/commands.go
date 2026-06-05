package tui

import (
	"fmt"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// deriveDomain guesses the domain from the finding ID and layers.
func deriveDomain(f schema.Finding) string {
	id := strings.ToUpper(f.ID)
	// explicit ID prefixes
	if strings.Contains(id, "-CI-") {
		return "ci"
	}
	if strings.Contains(id, "-RUNTIME-") || strings.Contains(id, "-DECL-") {
		return "runtime"
	}
	if strings.Contains(id, "-ENV-") {
		return "env"
	}
	if strings.Contains(id, "-PORT-") || strings.Contains(id, "-NETWORK-") {
		return "network"
	}
	if strings.Contains(id, "-SECURITY-") {
		return "security"
	}
	if strings.Contains(id, "-CONTAINER-") || strings.Contains(id, "-DOCKER-") || strings.Contains(id, "-PODMAN-") {
		return "containers"
	}
	if strings.Contains(id, "-GPU-") || strings.Contains(id, "-CUDA-") {
		return "gpu"
	}
	if strings.Contains(id, "-CACHE-") {
		return "cache"
	}
	if strings.Contains(id, "-HOST-") {
		return "host"
	}
	if strings.Contains(id, "-PERMISSION-") {
		return "permissions"
	}
	if strings.Contains(id, "-GIT-") {
		return "git"
	}
	if strings.Contains(id, "-CONFIG-") {
		return "config"
	}
	if strings.Contains(id, "-TRACE-") {
		return "trace"
	}
	// fallback to layers
	for _, l := range f.Layers {
		l = strings.ToLower(l)
		switch l {
		case "ci":
			return "ci"
		case "local", "runtime":
			return "runtime"
		case "env":
			return "env"
		case "network", "port":
			return "network"
		case "security":
			return "security"
		case "container", "docker", "podman":
			return "containers"
		case "gpu", "cuda":
			return "gpu"
		case "cache":
			return "cache"
		case "host":
			return "host"
		case "permission":
			return "permissions"
		case "git":
			return "git"
		case "config":
			return "config"
		}
	}
	return "general"
}

// deriveTarget describes the primary target of a finding.
func deriveTarget(f schema.Finding) string {
	domain := deriveDomain(f)
	switch domain {
	case "ci":
		return "CI pipeline"
	case "runtime":
		return "local runtime"
	case "env":
		return "environment"
	case "network":
		return "network services"
	case "security":
		return "security posture"
	case "containers":
		return "container environment"
	case "gpu":
		return "GPU/ML stack"
	case "cache":
		return "build cache"
	case "host":
		return "host system"
	case "permissions":
		return "file permissions"
	case "git":
		return "repository"
	case "config":
		return "configuration"
	}
	return "project"
}

// deriveBlastRadius estimates blast radius from severity and domain.
func deriveBlastRadius(f schema.Finding) string {
	switch f.Severity {
	case schema.SeverityCritical:
		return "high"
	case schema.SeverityHigh:
		return "high"
	case schema.SeverityMedium:
		return "medium"
	case schema.SeverityLow:
		return "low"
	default:
		return "low"
	}
}

// deriveMutationRisk estimates mutation risk from fix hints.
func deriveMutationRisk(f schema.Finding) string {
	for _, h := range f.FixHints {
		hl := strings.ToLower(h)
		if strings.Contains(hl, "destructive") || strings.Contains(hl, "delete") || strings.Contains(hl, "remove") || strings.Contains(hl, "rm") {
			return "high"
		}
		if strings.Contains(hl, "safe") || strings.Contains(hl, "restart") || strings.Contains(hl, "reconfigure") || strings.Contains(hl, "edit") {
			return "low"
		}
	}
	for _, fix := range f.Fixes {
		fl := strings.ToLower(fix.Title)
		if strings.Contains(fl, "destructive") || strings.Contains(fl, "delete") || strings.Contains(fl, "remove") {
			return "high"
		}
		if strings.Contains(fl, "safe") || strings.Contains(fl, "restart") || strings.Contains(fl, "reconfigure") {
			return "low"
		}
	}
	// Default based on severity
	if f.Severity == schema.SeverityCritical || f.Severity == schema.SeverityHigh {
		return "medium"
	}
	return "low"
}

// deriveReasoning builds a short explanation from available fields.
func deriveReasoning(f schema.Finding) []string {
	var out []string
	if f.Symptom != "" {
		out = append(out, f.Symptom)
	}
	for _, c := range f.LikelyCauses {
		out = append(out, c)
	}
	if len(out) == 0 {
		out = append(out, "Derived from evidence and rule evaluation.")
	}
	return out
}

// deriveCommandHints generates only real devdiag commands.
func deriveCommandHints(f InspectFinding) []CommandHint {
	var hints []CommandHint
	pathPlaceholder := "."

	switch f.Domain {
	case "ci":
		hints = append(hints, CommandHint{
			Title:        "Check CI configuration",
			Command:      fmt.Sprintf("devdiag check ci %s --verbose", pathPlaceholder),
			Kind:         "check",
			MutationRisk: "none",
		})
	case "containers":
		hints = append(hints, CommandHint{
			Title:        "Check containers",
			Command:      fmt.Sprintf("devdiag check containers %s --verbose", pathPlaceholder),
			Kind:         "check",
			MutationRisk: "none",
		})
	case "security":
		hints = append(hints, CommandHint{
			Title:        "Check security posture",
			Command:      fmt.Sprintf("devdiag check security %s --verbose", pathPlaceholder),
			Kind:         "check",
			MutationRisk: "none",
		})
	case "gpu":
		hints = append(hints, CommandHint{
			Title:        "Check GPU stack",
			Command:      fmt.Sprintf("devdiag check gpu %s --verbose", pathPlaceholder),
			Kind:         "check",
			MutationRisk: "none",
		})
	case "cache":
		hints = append(hints, CommandHint{
			Title:        "Check cache configuration",
			Command:      fmt.Sprintf("devdiag check cache %s --verbose", pathPlaceholder),
			Kind:         "check",
			MutationRisk: "none",
		})
	case "network":
		hints = append(hints, CommandHint{
			Title:        "Check network ports",
			Command:      fmt.Sprintf("devdiag check ports %s --verbose", pathPlaceholder),
			Kind:         "check",
			MutationRisk: "none",
		})
	default:
		hints = append(hints, CommandHint{
			Title:        "Re-scan with verbose output",
			Command:      fmt.Sprintf("devdiag scan %s --verbose", pathPlaceholder),
			Kind:         "scan",
			MutationRisk: "none",
		})
	}

	// Add a fix dry-run hint for any finding with a fix
	if len(f.Finding.Fixes) > 0 {
		hints = append(hints, CommandHint{
			Title:        fmt.Sprintf("Plan fix for %s", f.Finding.ID),
			Command:      fmt.Sprintf("devdiag fix %s --dry-run", f.Finding.ID),
			Kind:         "fix",
			MutationRisk: f.MutationRisk,
		})
	}

	return hints
}

// deriveRelatedResources extracts resources from evidence when available.
func deriveRelatedResources(f InspectFinding) []RelatedResource {
	var out []RelatedResource
	for _, ev := range f.Finding.Evidence {
		if strings.HasPrefix(ev.Source, "url_") || strings.Contains(ev.Value, "http") {
			out = append(out, RelatedResource{Kind: "url", Value: ev.Value})
		}
		if strings.HasSuffix(ev.Source, "_file") || strings.Contains(ev.Source, "path") {
			out = append(out, RelatedResource{Kind: "file", Value: ev.Value})
		}
	}
	return out
}
