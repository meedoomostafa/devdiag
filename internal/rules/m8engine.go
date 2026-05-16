package rules

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/graph"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// M8Engine evaluates CI/local parity policies.
type M8Engine struct{}

// NewM8Engine creates a new M8 engine.
func NewM8Engine() *M8Engine {
	return &M8Engine{}
}

// Evaluate checks CI evidence against local evidence for parity drift.
func (e *M8Engine) Evaluate(snapshot graph.NormalizedSnapshot) ([]schema.Finding, error) {
	var findings []schema.Finding

	var ciEvidence []schema.Evidence
	var runtimeEvs map[string]string
	var envEvs []schema.Evidence
	var composeEvs []schema.Evidence
	var hostShell string
	var devcontainerImage string

	for _, c := range snapshot.Collectors {
		switch c.Name {
		case "ci":
			ciEvidence = append(ciEvidence, c.Evidence...)
		case "runtime":
			runtimeEvs = make(map[string]string)
			for _, ev := range c.Evidence {
				runtimeEvs[ev.Source] = ev.Value
			}
		case "env":
			envEvs = append(envEvs, c.Evidence...)
		case "compose":
			composeEvs = append(composeEvs, c.Evidence...)
		case "host":
			for _, ev := range c.Evidence {
				if ev.Source == "host_shell" {
					hostShell = ev.Value
				}
			}
		case "repo":
			for _, ev := range c.Evidence {
				if ev.Source == "devcontainer_image" {
					devcontainerImage = ev.Value
				}
			}
		}
	}

	if len(ciEvidence) == 0 {
		return findings, nil
	}

	// Collect setup actions for runtime comparison
	var ciSetupActions []schema.Evidence
	for _, ev := range ciEvidence {
		if strings.HasPrefix(ev.Source, "ci_setup__") {
			ciSetupActions = append(ciSetupActions, ev)
		}
	}

	// Collect all CI env keys
	allCIEnvKeys := make(map[string]bool)
	for _, ev := range ciEvidence {
		if key, ok := ciEnvKey(ev.Source); ok {
			allCIEnvKeys[key] = true
		}
	}

	// Collect local env keys from .env and .env.example
	localEnvKeys := make(map[string]bool)
	for _, ev := range envEvs {
		if ev.Source == ".env" && strings.HasPrefix(ev.Value, "keys: ") {
			keys := strings.Split(strings.TrimPrefix(ev.Value, "keys: "), ", ")
			for _, k := range keys {
				localEnvKeys[k] = true
			}
		}
		if ev.Source == ".env.example" && strings.HasPrefix(ev.Value, "keys: ") {
			keys := strings.Split(strings.TrimPrefix(ev.Value, "keys: "), ", ")
			for _, k := range keys {
				localEnvKeys[k] = true
			}
		}
	}

	// Collect compose host ports
	composePorts := make(map[int]bool)
	for _, ev := range composeEvs {
		if ev.Source == "compose_host_port" {
			if p, err := strconv.Atoi(ev.Value); err == nil && p > 0 {
				composePorts[p] = true
			}
		}
	}

	// Collect CI service ports
	var ciServices []schema.Evidence
	for _, ev := range ciEvidence {
		if strings.HasPrefix(ev.Source, "ci_service__") && strings.HasSuffix(ev.Source, "__host_port") {
			ciServices = append(ciServices, ev)
		}
	}

	// Collect CI containers
	var ciContainers []schema.Evidence
	for _, ev := range ciEvidence {
		if strings.HasPrefix(ev.Source, "ci_container__") && strings.HasSuffix(ev.Source, "__image") {
			ciContainers = append(ciContainers, ev)
		}
	}

	// Collect CI shells
	var ciShells []schema.Evidence
	for _, ev := range ciEvidence {
		if ev.Source == "ci_defaults__workflow__shell" ||
			(strings.HasPrefix(ev.Source, "ci_defaults__job__") && strings.HasSuffix(ev.Source, "__shell")) {
			ciShells = append(ciShells, ev)
		}
	}

	// Parse local runtimes
	localRuntimes := extractLocalRuntimes(runtimeEvs)

	// Compare CI setup action versions with local runtime declarations
	for _, ev := range ciSetupActions {
		actionName, ok := ciSetupInfo(ev.Source)
		if !ok {
			continue
		}
		ciVal := ev.Value
		localRT := localRuntimes[actionName]
		if localRT == "" {
			findings = append(findings, schema.Finding{
				ID:         "F-CI-PACKAGE-001",
				Title:      fmt.Sprintf("CI uses %s but repo has no local runtime pin", actionName),
				Severity:   schema.SeverityLow,
				Confidence: 0.5,
				Symptom:    fmt.Sprintf("CI configures %s=%s but no .nvmrc/.python-version/go.mod version matches", actionName, ciVal),
				Evidence: []schema.Evidence{
					{Source: ev.Source, Value: ciVal},
				},
				LikelyCauses: []string{
					"Add a local runtime pin file so dev and CI stay in sync",
				},
			})
			continue
		}
		if !versionsCompatible(localRT, ciVal) {
			findings = append(findings, schema.Finding{
				ID:         "F-CI-RUNTIME-001",
				Title:      fmt.Sprintf("CI %s version %s differs from local %s", actionName, ciVal, localRT),
				Severity:   schema.SeverityMedium,
				Confidence: 0.7,
				Symptom:    fmt.Sprintf("Version mismatch: CI uses %s=%s, local runtime pin is %s", actionName, ciVal, localRT),
				Evidence: []schema.Evidence{
					{Source: ev.Source, Value: ciVal},
					{Source: "local_runtime", Value: localRT},
				},
				LikelyCauses: []string{
					"Runtime versions drifted between CI and local dev environment",
				},
			})
		}
	}

	// Check env parity
	for key := range allCIEnvKeys {
		if !localEnvKeys[key] {
			findings = append(findings, schema.Finding{
				ID:         "F-CI-ENV-001",
				Title:      fmt.Sprintf("CI env var %s not found locally", key),
				Severity:   schema.SeverityMedium,
				Confidence: 0.6,
				Symptom:    fmt.Sprintf("Environment variable %s is set in CI but missing from local .env", key),
				Evidence: []schema.Evidence{
					{Source: "ci_env", Value: key},
					{Source: ".env", Value: "missing"},
				},
				LikelyCauses: []string{
					"Local .env is out of date with CI configuration",
				},
			})
		}
	}

	for key := range localEnvKeys {
		if !allCIEnvKeys[key] {
			findings = append(findings, schema.Finding{
				ID:         "F-CI-ENV-002",
				Title:      fmt.Sprintf("Local env var %s not found in CI", key),
				Severity:   schema.SeverityLow,
				Confidence: 0.5,
				Symptom:    fmt.Sprintf("Environment variable %s exists locally but is not referenced in CI", key),
				Evidence: []schema.Evidence{
					{Source: ".env", Value: key},
					{Source: "ci_env", Value: "missing"},
				},
				LikelyCauses: []string{
					"CI workflow may be missing required environment variables",
				},
			})
		}
	}

	// Check service port parity
	for _, ev := range ciServices {
		service, port, ok := ciServicePort(ev.Source, ev.Value)
		if !ok {
			continue
		}
		if !composePorts[port] {
			findings = append(findings, schema.Finding{
				ID:         "F-CI-SERVICE-001",
				Title:      fmt.Sprintf("CI service %s port %d not exposed locally", service, port),
				Severity:   schema.SeverityMedium,
				Confidence: 0.6,
				Symptom:    fmt.Sprintf("CI defines service %s on port %d but local compose does not expose it", service, port),
				Evidence: []schema.Evidence{
					{Source: ev.Source, Value: ev.Value},
				},
				LikelyCauses: []string{
					"Local compose.yaml is missing service port mapping",
				},
			})
		}
	}

	// Check container vs devcontainer drift
	for _, ev := range ciContainers {
		if devcontainerImage == "" {
			continue
		}
		if !strings.Contains(ev.Value, devcontainerImage) && !strings.Contains(devcontainerImage, ev.Value) {
			findings = append(findings, schema.Finding{
				ID:         "F-CI-CONTAINER-001",
				Title:      "CI container image differs from devcontainer image",
				Severity:   schema.SeverityMedium,
				Confidence: 0.6,
				Symptom:    "CI job container image does not match the devcontainer configuration",
				Evidence: []schema.Evidence{
					{Source: ev.Source, Value: ev.Value},
					{Source: "devcontainer_image", Value: devcontainerImage},
				},
				LikelyCauses: []string{"Devcontainer and CI images drifted out of sync"},
			})
		}
	}

	// Check shell mismatch
	if hostShell != "" {
		for _, ev := range ciShells {
			if ev.Value != hostShell {
				findings = append(findings, schema.Finding{
					ID:         "F-CI-SHELL-001",
					Title:      fmt.Sprintf("CI shell %s differs from host shell %s", ev.Value, hostShell),
					Severity:   schema.SeverityLow,
					Confidence: 0.5,
					Symptom:    "CI default shell may behave differently from local shell",
					Evidence: []schema.Evidence{
						{Source: ev.Source, Value: ev.Value},
						{Source: "host_shell", Value: hostShell},
					},
					LikelyCauses: []string{
						"Shell-specific syntax may behave differently in CI",
					},
				})
			}
		}
	}

	return findings, nil
}

func ciEnvKey(source string) (key string, ok bool) {
	if strings.HasPrefix(source, "ci_env__workflow__") {
		return strings.TrimPrefix(source, "ci_env__workflow__"), true
	}
	if strings.HasPrefix(source, "ci_env__job__") {
		parts := strings.SplitN(strings.TrimPrefix(source, "ci_env__job__"), "__", 2)
		if len(parts) == 2 {
			return parts[1], true
		}
	}
	if strings.HasPrefix(source, "ci_env__step__") {
		parts := strings.SplitN(strings.TrimPrefix(source, "ci_env__step__"), "__", 3)
		if len(parts) == 3 {
			return parts[2], true
		}
	}
	return "", false
}

func ciSetupInfo(source string) (actionName string, ok bool) {
	if !strings.HasPrefix(source, "ci_setup__") {
		return "", false
	}
	parts := strings.Split(strings.TrimPrefix(source, "ci_setup__"), "__")
	if len(parts) < 4 {
		return "", false
	}
	return actionRuntimeKey(parts[2]), true
}

func ciServicePort(source, value string) (service string, port int, ok bool) {
	if !strings.HasPrefix(source, "ci_service__") || !strings.HasSuffix(source, "__host_port") {
		return "", 0, false
	}
	parts := strings.Split(strings.TrimPrefix(source, "ci_service__"), "__")
	if len(parts) != 3 {
		return "", 0, false
	}
	p, err := strconv.Atoi(value)
	if err != nil || p <= 0 {
		return "", 0, false
	}
	return parts[1], p, true
}

func actionRuntimeKey(action string) string {
	switch action {
	case "setup_node":
		return "setup-node"
	case "setup_python":
		return "setup-python"
	case "setup_go":
		return "setup-go"
	case "setup_ruby":
		return "setup-ruby"
	}
	return action
}

func extractLocalRuntimes(runtimeEvs map[string]string) map[string]string {
	result := make(map[string]string)
	for src, val := range runtimeEvs {
		switch src {
		case ".nvmrc":
			result["setup-node"] = normalizeVersion(strings.TrimPrefix(val, "node "))
		case ".python-version":
			result["setup-python"] = normalizeVersion(strings.TrimPrefix(val, "python "))
		case "go.mod":
			result["setup-go"] = normalizeVersion(strings.TrimPrefix(val, "go "))
		case ".ruby-version":
			result["setup-ruby"] = normalizeVersion(strings.TrimPrefix(val, "ruby "))
		case "package.json":
			if strings.Contains(val, "engines:") {
				engines := strings.TrimPrefix(val, "engines: ")
				for _, part := range strings.Split(engines, ",") {
					part = strings.TrimSpace(part)
					if strings.HasPrefix(part, `"node"`) {
						// "node": ">=20"  -> >=20
						ep := strings.Split(part, ":")
						if len(ep) == 2 {
							ver := strings.Trim(strings.TrimSpace(ep[1]), `"`)
							if ver != "" {
								result["setup-node"] = normalizeVersion(ver)
							}
						}
					}
				}
			}
		}
	}
	return result
}
