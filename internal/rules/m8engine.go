package rules

import (
	"fmt"
	"sort"
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
	var repoEvs []schema.Evidence
	ignoreMissingLocal := make(map[string]bool)
	ignoreMissingCI := make(map[string]bool)
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
				repoEvs = append(repoEvs, ev)
				if ev.Source == "devcontainer_image" {
					devcontainerImage = ev.Value
				}
			}
		case "config":
			collectM8Config(c.Evidence, ignoreMissingLocal, ignoreMissingCI)
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
	ciRunCommands := collectCIRunCommands(ciEvidence)
	localCommands := collectRepoCommands(repoEvs)
	repoPackageManager := collectRepoPackageManager(repoEvs)

	allCIEnvKeys := make(map[string]bool)
	for _, ev := range ciEvidence {
		if key, ok := ciEnvKey(ev.Source); ok {
			if isIgnoredCIEnv(key, ev.Value) {
				continue
			}
			if ignoreMissingLocal[key] {
				continue
			}
			allCIEnvKeys[key] = true
		}
	}

	localEnvKeys := make(map[string]bool)
	localEnvKeysForCI := make(map[string]bool)
	for _, ev := range envEvs {
		if ev.Source == ".env" || ev.Source == ".env.example" || ev.Source == ".env.local" || (strings.HasPrefix(ev.Source, ".env.") && strings.HasSuffix(ev.Source, ".example")) {
			for _, k := range envKeysFromEvidence(ev.Value) {
				localEnvKeys[k] = true
				if envSourceRequiresCI(ev.Source) {
					if ignoreMissingCI[k] {
						continue
					}
					localEnvKeysForCI[k] = true
				}
			}
		}
	}

	composePorts := make(map[int]bool)
	for _, ev := range composeEvs {
		if ev.Source == "compose_host_port" {
			if p, err := strconv.Atoi(ev.Value); err == nil && p > 0 {
				composePorts[p] = true
			}
		}
	}
	ciServices := collectCIServices(ciEvidence)
	composeServices := collectComposeServices(composeEvs)

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
		if isOpaqueCIValue(ciVal) {
			continue
		}
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

	for _, ciCmd := range ciRunCommands {
		ciPM := commandPackageManager(ciCmd.Value)
		if repoPackageManager != "" && ciPM != "" && ciPM != packageManagerName(repoPackageManager) && localCommandWithSameArgs(ciCmd.Value, localCommands) {
			findings = append(findings, schema.Finding{
				ID:         "F-CI-PACKAGE-002",
				Title:      fmt.Sprintf("CI command package manager differs from local %s", repoPackageManager),
				Severity:   schema.SeverityLow,
				Confidence: 0.6,
				Symptom:    fmt.Sprintf("CI runs %s but repo package manager is %s", ciCmd.Value, repoPackageManager),
				Evidence: []schema.Evidence{
					ciCmd,
					{Source: "repo_package_manager", Value: repoPackageManager},
				},
				LikelyCauses: []string{
					"CI workflow may use a stale package manager command",
				},
			})
			continue
		}
		if len(localCommands) > 0 && !localCommandMatches(ciCmd.Value, localCommands) {
			findings = append(findings, schema.Finding{
				ID:         "F-CI-COMMAND-001",
				Title:      fmt.Sprintf("CI command %s is not documented locally", summarizeCommandForTitle(ciCmd.Value)),
				Severity:   schema.SeverityLow,
				Confidence: 0.5,
				Symptom:    "CI run command does not match collected local README/package/Makefile/Taskfile/justfile commands",
				Evidence: []schema.Evidence{
					ciCmd,
				},
				LikelyCauses: []string{
					"Local command documentation may be out of sync with CI",
				},
			})
		}
	}

	// Check env parity
	var missingLocalKeys []string
	for key := range allCIEnvKeys {
		if !localEnvKeys[key] {
			missingLocalKeys = append(missingLocalKeys, key)
		}
	}
	if len(missingLocalKeys) > 0 {
		sort.Strings(missingLocalKeys)
		findings = append(findings, schema.Finding{
			ID:         "F-CI-ENV-001",
			Title:      fmt.Sprintf("CI env vars not found locally: %s", summarizeKeysForTitle(missingLocalKeys)),
			Severity:   schema.SeverityMedium,
			Confidence: 0.6,
			Symptom:    "One or more environment variables are set in CI but missing from local .env evidence",
			Evidence:   envKeyEvidence("ci_env", missingLocalKeys),
			LikelyCauses: []string{
				"Local .env is out of date with CI configuration",
			},
		})
	}

	var missingCIKeys []string
	for key := range localEnvKeysForCI {
		if !allCIEnvKeys[key] {
			missingCIKeys = append(missingCIKeys, key)
		}
	}
	if len(missingCIKeys) > 0 {
		sort.Strings(missingCIKeys)
		findings = append(findings, schema.Finding{
			ID:         "F-CI-ENV-002",
			Title:      fmt.Sprintf("Local env vars not found in CI: %s", summarizeKeysForTitle(missingCIKeys)),
			Severity:   schema.SeverityLow,
			Confidence: 0.5,
			Symptom:    "One or more local .env variables are not referenced in CI",
			Evidence:   envKeyEvidence(".env", missingCIKeys),
			LikelyCauses: []string{
				"CI workflow may be missing required environment variables",
			},
		})
	}

	for name, ciService := range ciServices {
		composeService, ok := composeServices[name]
		if !ok {
			if len(composeServices) == 0 && legacyComposePortMatch(ciService, composePorts) {
				continue
			}
			findings = append(findings, schema.Finding{
				ID:         "F-CI-SERVICE-001",
				Title:      fmt.Sprintf("CI service %s is not matched locally", name),
				Severity:   schema.SeverityMedium,
				Confidence: 0.6,
				Symptom:    fmt.Sprintf("CI defines service %s but local compose does not define a matching service", name),
				Evidence:   ciService.Evidence,
				LikelyCauses: []string{
					"Local compose.yaml is missing a matching service definition",
				},
			})
			continue
		}
		if serviceMismatch(ciService, composeService) {
			findings = append(findings, schema.Finding{
				ID:         "F-CI-SERVICE-001",
				Title:      fmt.Sprintf("CI service %s differs from local compose service", name),
				Severity:   schema.SeverityMedium,
				Confidence: 0.6,
				Symptom:    fmt.Sprintf("CI service %s image or ports do not match local compose", name),
				Evidence:   append(ciService.Evidence, composeService.Evidence...),
				LikelyCauses: []string{
					"CI and local compose service definitions drifted",
				},
			})
		}
	}

	for name, composeService := range composeServices {
		if _, ok := ciServices[name]; ok {
			continue
		}
		findings = append(findings, schema.Finding{
			ID:         "F-CI-SERVICE-002",
			Title:      fmt.Sprintf("Local compose service %s is not defined in CI", name),
			Severity:   schema.SeverityLow,
			Confidence: 0.5,
			Symptom:    fmt.Sprintf("Local compose defines service %s but CI does not define a matching service", name),
			Evidence:   composeService.Evidence,
			LikelyCauses: []string{
				"CI workflow may not start a local dependency required during development",
			},
		})
	}

	// Check container vs devcontainer drift
	for _, ev := range ciContainers {
		if devcontainerImage == "" {
			continue
		}
		if normalizeContainerImage(ev.Value) != normalizeContainerImage(devcontainerImage) {
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
		return decodeSourceSegment(strings.TrimPrefix(source, "ci_env__workflow__")), true
	}
	if strings.HasPrefix(source, "ci_env__job__") {
		rest := strings.TrimPrefix(source, "ci_env__job__")
		if idx := strings.LastIndex(rest, "__"); idx != -1 {
			return decodeSourceSegment(rest[idx+2:]), true
		}
	}
	if strings.HasPrefix(source, "ci_env__step__") {
		rest := strings.TrimPrefix(source, "ci_env__step__")
		if idx := strings.LastIndex(rest, "__"); idx != -1 {
			return decodeSourceSegment(rest[idx+2:]), true
		}
	}
	return "", false
}

func collectM8Config(evidence []schema.Evidence, ignoreMissingLocal, ignoreMissingCI map[string]bool) {
	for _, ev := range evidence {
		key := strings.TrimSpace(ev.Value)
		if key == "" {
			continue
		}
		switch ev.Source {
		case "devdiag_ci_env_ignore_missing_local":
			ignoreMissingLocal[key] = true
		case "devdiag_ci_env_ignore_missing_ci":
			ignoreMissingCI[key] = true
		}
	}
}

func summarizeCommandForTitle(command string) string {
	const maxTitleCommandLen = 80
	command = strings.Join(strings.Fields(command), " ")
	if len(command) <= maxTitleCommandLen {
		return command
	}
	return strings.TrimSpace(command[:maxTitleCommandLen-3]) + "..."
}

func summarizeKeysForTitle(keys []string) string {
	const maxKeysInTitle = 5
	if len(keys) <= maxKeysInTitle {
		return strings.Join(keys, ", ")
	}
	return fmt.Sprintf("%s, and %d more", strings.Join(keys[:maxKeysInTitle], ", "), len(keys)-maxKeysInTitle)
}

func envKeyEvidence(source string, keys []string) []schema.Evidence {
	evidence := make([]schema.Evidence, 0, len(keys))
	for _, key := range keys {
		evidence = append(evidence, schema.Evidence{Source: source, Value: key})
	}
	return evidence
}

func ciSetupInfo(source string) (actionName string, ok bool) {
	if !strings.HasPrefix(source, "ci_setup__") {
		return "", false
	}
	parts := strings.Split(strings.TrimPrefix(source, "ci_setup__"), "__")
	if len(parts) < 4 {
		return "", false
	}
	return actionRuntimeKey(decodeSourceSegment(parts[len(parts)-2])), true
}

func ciServicePort(source, value string) (service string, port int, ok bool) {
	if !strings.HasPrefix(source, "ci_service__") || !strings.HasSuffix(source, "__host_port") {
		return "", 0, false
	}
	rest := strings.TrimSuffix(strings.TrimPrefix(source, "ci_service__"), "__host_port")
	idx := strings.LastIndex(rest, "__")
	if idx == -1 {
		return "", 0, false
	}
	p, err := strconv.Atoi(value)
	if err != nil || p <= 0 {
		return "", 0, false
	}
	return decodeSourceSegment(rest[idx+2:]), p, true
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
	case "setup_dotnet":
		return "setup-dotnet"
	}
	return action
}

func extractLocalRuntimes(runtimeEvs map[string]string) map[string]string {
	result := make(map[string]string)
	for src, val := range runtimeEvs {
		switch src {
		case ".nvmrc":
			result["setup-node"] = strings.TrimSpace(strings.TrimPrefix(val, "node "))
		case ".python-version":
			result["setup-python"] = strings.TrimSpace(strings.TrimPrefix(val, "python "))
		case "go.mod":
			result["setup-go"] = strings.TrimSpace(strings.TrimPrefix(val, "go "))
		case ".ruby-version":
			result["setup-ruby"] = strings.TrimSpace(strings.TrimPrefix(val, "ruby "))
		case "global.json":
			result["setup-dotnet"] = strings.TrimSpace(strings.TrimPrefix(val, "dotnet "))
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
								result["setup-node"] = ver
							}
						}
					}
				}
			}
		}
	}
	return result
}

func decodeSourceSegment(s string) string {
	return strings.ReplaceAll(s, "%5F%5F", "__")
}

func isOpaqueCIValue(value string) bool {
	return strings.Contains(value, "${{")
}

func collectCIRunCommands(evidence []schema.Evidence) []schema.Evidence {
	var commands []schema.Evidence
	for _, ev := range evidence {
		if strings.HasPrefix(ev.Source, "ci_run__") {
			commands = append(commands, ev)
		}
	}
	return commands
}

func collectRepoCommands(evidence []schema.Evidence) []schema.Evidence {
	var commands []schema.Evidence
	for _, ev := range evidence {
		if strings.HasPrefix(ev.Source, "repo_command__") {
			commands = append(commands, ev)
		}
	}
	return commands
}

func collectRepoPackageManager(evidence []schema.Evidence) string {
	for _, ev := range evidence {
		if ev.Source == "repo_package_manager" {
			return ev.Value
		}
	}
	return ""
}

func commandPackageManager(command string) string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return ""
	}
	switch fields[0] {
	case "npm", "pnpm", "yarn", "bun":
		return fields[0]
	default:
		return ""
	}
}

func packageManagerName(pm string) string {
	if idx := strings.Index(pm, "@"); idx != -1 {
		return pm[:idx]
	}
	return pm
}

func localCommandMatches(command string, localCommands []schema.Evidence) bool {
	normalized := normalizeCommand(command)
	for _, ev := range localCommands {
		if normalizeCommand(ev.Value) == normalized {
			return true
		}
	}
	return false
}

func localCommandWithSameArgs(command string, localCommands []schema.Evidence) bool {
	targetArgs := commandWithoutPackageManager(command)
	if targetArgs == "" {
		return false
	}
	for _, ev := range localCommands {
		if commandWithoutPackageManager(ev.Value) == targetArgs {
			return true
		}
	}
	return false
}

func commandWithoutPackageManager(command string) string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return ""
	}
	if commandPackageManager(command) == "" {
		return normalizeCommand(command)
	}
	return strings.Join(fields[1:], " ")
}

func normalizeCommand(command string) string {
	return strings.Join(strings.Fields(command), " ")
}

type m8ServiceSpec struct {
	Name           string
	Image          string
	HostPorts      map[int]bool
	ContainerPorts map[int]bool
	Evidence       []schema.Evidence
}

func collectCIServices(evidence []schema.Evidence) map[string]m8ServiceSpec {
	services := make(map[string]m8ServiceSpec)
	for _, ev := range evidence {
		name, field, ok := parseCIServiceEvidenceSource(ev.Source)
		if !ok {
			continue
		}
		spec := services[name]
		if spec.Name == "" {
			spec = newM8ServiceSpec(name)
		}
		applyServiceEvidence(&spec, field, ev)
		services[name] = spec
	}
	return services
}

func parseCIServiceEvidenceSource(source string) (name, field string, ok bool) {
	if !strings.HasPrefix(source, "ci_service__") {
		return "", "", false
	}
	rest := strings.TrimPrefix(source, "ci_service__")
	parts := strings.Split(rest, "__")
	if len(parts) < 2 {
		return "", "", false
	}
	field = parts[len(parts)-1]
	service := parts[0]
	if len(parts) >= 3 {
		service = parts[len(parts)-2]
	}
	if service == "" || field == "" {
		return "", "", false
	}
	return decodeSourceSegment(service), field, true
}

func collectComposeServices(evidence []schema.Evidence) map[string]m8ServiceSpec {
	services := make(map[string]m8ServiceSpec)
	for _, ev := range evidence {
		name, field, ok := parseServiceEvidenceSource(ev.Source, "compose_service__")
		if !ok {
			continue
		}
		spec := services[name]
		if spec.Name == "" {
			spec = newM8ServiceSpec(name)
		}
		applyServiceEvidence(&spec, field, ev)
		services[name] = spec
	}
	return services
}

func newM8ServiceSpec(name string) m8ServiceSpec {
	return m8ServiceSpec{
		Name:           name,
		HostPorts:      make(map[int]bool),
		ContainerPorts: make(map[int]bool),
	}
}

func parseServiceEvidenceSource(source, prefix string) (name, field string, ok bool) {
	if !strings.HasPrefix(source, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(source, prefix)
	idx := strings.LastIndex(rest, "__")
	if idx == -1 {
		return "", "", false
	}
	return decodeSourceSegment(rest[:idx]), rest[idx+2:], true
}

func applyServiceEvidence(spec *m8ServiceSpec, field string, ev schema.Evidence) {
	spec.Evidence = append(spec.Evidence, ev)
	switch field {
	case "image":
		spec.Image = strings.TrimSpace(ev.Value)
	case "host_port":
		if port, ok := parsePortInt(ev.Value); ok {
			spec.HostPorts[port] = true
		}
	case "container_port":
		if port, ok := parsePortInt(ev.Value); ok {
			spec.ContainerPorts[port] = true
		}
	}
}

func parsePortInt(value string) (int, bool) {
	value = strings.TrimSpace(value)
	value = strings.SplitN(value, "/", 2)[0]
	port, err := strconv.Atoi(value)
	return port, err == nil && port > 0
}

func legacyComposePortMatch(ciService m8ServiceSpec, composePorts map[int]bool) bool {
	for port := range ciService.HostPorts {
		if composePorts[port] {
			return true
		}
	}
	return false
}

func serviceMismatch(ciService, composeService m8ServiceSpec) bool {
	if ciService.Image != "" && composeService.Image != "" && normalizeContainerImage(ciService.Image) != normalizeContainerImage(composeService.Image) {
		return true
	}
	if len(ciService.HostPorts) > 0 && len(composeService.HostPorts) > 0 && !portsOverlap(ciService.HostPorts, composeService.HostPorts) {
		return true
	}
	if len(ciService.ContainerPorts) > 0 && len(composeService.ContainerPorts) > 0 && !portsOverlap(ciService.ContainerPorts, composeService.ContainerPorts) {
		return true
	}
	return false
}

func portsOverlap(left, right map[int]bool) bool {
	for port := range left {
		if right[port] {
			return true
		}
	}
	return false
}

func envKeysFromEvidence(value string) []string {
	if !strings.HasPrefix(value, "keys: ") {
		return nil
	}
	raw := strings.TrimPrefix(value, "keys: ")
	parts := strings.Split(raw, ",")
	keys := make([]string, 0, len(parts))
	for _, part := range parts {
		key := strings.TrimSpace(part)
		if key != "" {
			keys = append(keys, key)
		}
	}
	return keys
}

func envSourceRequiresCI(source string) bool {
	return source == ".env"
}

func isIgnoredCIEnv(key, value string) bool {
	if key == "" {
		return true
	}
	if key == "CI" || key == "GITHUB_TOKEN" {
		return true
	}
	if strings.HasPrefix(key, "GITHUB_") || strings.HasPrefix(key, "RUNNER_") || strings.HasPrefix(key, "ACTIONS_") {
		return true
	}
	value = strings.TrimSpace(value)
	return strings.HasPrefix(value, "${{ github.") || strings.HasPrefix(value, "${{ runner.") || strings.HasPrefix(value, "${{ env.")
}

func normalizeContainerImage(image string) string {
	image = strings.TrimSpace(strings.ToLower(image))
	if image == "" {
		return ""
	}
	if idx := strings.Index(image, "@"); idx != -1 {
		image = image[:idx]
	}
	if !strings.Contains(image, ":") || strings.LastIndex(image, ":") < strings.LastIndex(image, "/") {
		image += ":latest"
	}
	parts := strings.Split(image, "/")
	if len(parts) == 1 {
		return "docker.io/library/" + parts[0]
	}
	if len(parts) == 2 && !strings.Contains(parts[0], ".") && !strings.Contains(parts[0], ":") && parts[0] != "localhost" {
		return "docker.io/" + image
	}
	if strings.HasPrefix(image, "index.docker.io/") {
		image = strings.TrimPrefix(image, "index.")
	}
	return image
}
