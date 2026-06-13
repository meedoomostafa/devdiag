package rules

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/graph"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// M1Engine is the Milestone 1+2 Go rule engine behind the PolicyEngine interface.
type M1Engine struct{}

// NewM1Engine creates the M1 rule engine.
func NewM1Engine() *M1Engine {
	return &M1Engine{}
}

// Evaluate converts collector evidence into findings.
func (e *M1Engine) Evaluate(snapshot graph.NormalizedSnapshot) ([]schema.Finding, error) {
	var findings []schema.Finding

	// Build collector lookup for cross-collector joins
	collectorMap := make(map[string]schema.CollectorResult)
	for _, c := range snapshot.Collectors {
		collectorMap[c.Name] = c
	}

	for _, c := range snapshot.Collectors {
		switch c.Name {
		case "env":
			findings = append(findings, e.envRules(c, collectorMap)...)
		case "compose":
			findings = append(findings, e.composeRules(c, collectorMap)...)
		case "git":
			findings = append(findings, e.gitRules(c)...)
		case "repo":
			findings = append(findings, e.repoRules(c)...)
		case "runtime":
			findings = append(findings, e.runtimeRules(c)...)
		case "ci":
			findings = append(findings, e.ciRules(c)...)
		case "host":
			// host metadata is evidence-only, no standalone findings
		case "host_runtime":
			findings = append(findings, e.hostRuntimeRules(c, collectorMap)...)
		case "disk":
			findings = append(findings, e.diskRules(c)...)
		case "port":
			findings = append(findings, e.portRules(c, collectorMap)...)
		case "network":
			findings = append(findings, e.networkRules(c)...)
		case "systemd":
			findings = append(findings, e.systemdRules(c)...)
		case "security":
			findings = append(findings, e.securityRules(c)...)
		case "permission":
			findings = append(findings, e.permissionRules(c)...)
		case "docker":
			findings = append(findings, e.dockerRules(c, collectorMap)...)
		case "podman":
			findings = append(findings, e.podmanRules(c)...)
		case "compose_status":
			findings = append(findings, e.composeStatusRules(c, collectorMap)...)
		case "repro":
			findings = append(findings, e.reproRules(c)...)
		case "self":
			// self collector produces no findings
		}
	}

	return findings, nil
}

// envRules creates findings from env collector evidence.
func (e *M1Engine) envRules(result schema.CollectorResult, collectors map[string]schema.CollectorResult) []schema.Finding {
	var findings []schema.Finding
	var envMissing, envExampleKeys []string

	ignoreMissing := make(map[string]bool)
	optionalKeys := make(map[string]bool)
	requiredKeys := make(map[string]bool)

	if configResult, ok := collectors["config"]; ok {
		for _, ev := range configResult.Evidence {
			switch ev.Source {
			case "devdiag_env_ignore_missing":
				ignoreMissing[ev.Value] = true
			case "devdiag_env_optional":
				optionalKeys[ev.Value] = true
			case "devdiag_env_required":
				requiredKeys[ev.Value] = true
			}
		}
	}

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
			var filteredMissing []string
			var filteredOptional []string
			for _, k := range missing {
				k = strings.TrimSpace(k)
				if k == "" {
					continue
				}
				if ignoreMissing[k] {
					continue
				}
				if len(requiredKeys) > 0 && !requiredKeys[k] {
					filteredOptional = append(filteredOptional, k)
					continue
				}
				if optionalKeys[k] {
					filteredOptional = append(filteredOptional, k)
					continue
				}
				filteredMissing = append(filteredMissing, k)
			}

			if len(filteredMissing) > 0 {
				findings = append(findings, schema.Finding{
					ID:           "F-ENV-001",
					Title:        fmt.Sprintf("Missing env keys from .env: %s", strings.Join(filteredMissing, ", ")),
					Severity:     schema.SeverityMedium,
					Confidence:   0.7,
					Symptom:      "Keys defined in .env.example are not present in .env",
					Evidence:     []schema.Evidence{{Source: "missing_keys", Value: strings.Join(filteredMissing, ", ")}},
					LikelyCauses: []string{".env file not created from .env.example"},
					FixHints:     []string{"add-env-placeholder"},
				})
			}
			if len(filteredOptional) > 0 {
				findings = append(findings, schema.Finding{
					ID:           "F-ENV-001-OPTIONAL",
					Title:        fmt.Sprintf("Optional env keys missing from .env: %s", strings.Join(filteredOptional, ", ")),
					Severity:     schema.SeverityInfo,
					Confidence:   0.7,
					Symptom:      "Optional keys defined in .env.example are not present in .env",
					Evidence:     []schema.Evidence{{Source: "missing_optional_keys", Value: strings.Join(filteredOptional, ", ")}},
					LikelyCauses: []string{"Optional env variables were not configured locally"},
				})
			}
		}
	}

	// Missing .env file entirely
	if len(envMissing) > 0 && len(envExampleKeys) > 0 {
		var activeExampleKeys []string
		for _, k := range envExampleKeys {
			k = strings.TrimSpace(k)
			if k != "" && !ignoreMissing[k] {
				activeExampleKeys = append(activeExampleKeys, k)
			}
		}
		if len(activeExampleKeys) > 0 {
			allOptional := true
			for _, k := range activeExampleKeys {
				if len(requiredKeys) > 0 && !requiredKeys[k] {
					continue
				}
				if !optionalKeys[k] {
					allOptional = false
					break
				}
			}
			sev := schema.SeverityMedium
			id := "F-ENV-001"
			if allOptional {
				sev = schema.SeverityInfo
				id = "F-ENV-001-OPTIONAL"
			}
			findings = append(findings, schema.Finding{
				ID:           id,
				Title:        ".env.example exists but no local .env was found",
				Severity:     sev,
				Confidence:   0.5,
				Symptom:      ".env.example exists but .env is missing",
				Evidence:     result.Evidence,
				LikelyCauses: []string{"Project may require local env vars but .env is not present"},
				FixHints:     []string{"add-env-placeholder"},
			})
		}
	}

	return findings
}

// composeRules creates findings from compose collector evidence.
func (e *M1Engine) composeRules(result schema.CollectorResult, collectors map[string]schema.CollectorResult) []schema.Finding {
	var findings []schema.Finding

	// Extract local env keys
	envKeys := make(map[string]bool)
	if envResult, ok := collectors["env"]; ok {
		for _, ev := range envResult.Evidence {
			if ev.Source == ".env" || ev.Source == ".env.local" {
				for _, k := range envKeysFromEvidence(ev.Value) {
					envKeys[k] = true
				}
			}
		}
	}

	// Map to group evidence by missing variable name
	missingVars := make(map[string][]schema.Evidence)

	for _, ev := range result.Evidence {
		// Only evaluate evidence that is a real Compose file line source
		if !strings.Contains(ev.Source, ".yaml:") && !strings.Contains(ev.Source, ".yml:") {
			continue
		}

		// Value is e.g. "services.api.environment.DB references ${DB:-default}"
		idx := strings.Index(ev.Value, " references ")
		if idx == -1 {
			continue
		}
		rawRef := ev.Value[idx+len(" references "):]

		varName, hasDefault := parseComposeRef(rawRef)
		if varName == "" {
			continue
		}

		// Suppress F-ENV-002 if:
		// 1. Defined in env files
		if envKeys[varName] {
			continue
		}
		// 2. Has a default or alternative form
		if hasDefault {
			continue
		}

		// Otherwise, it's missing!
		missingVars[varName] = append(missingVars[varName], ev)
	}

	// Create grouped findings sorted by varName for determinism
	var varNames []string
	for k := range missingVars {
		varNames = append(varNames, k)
	}
	sort.Strings(varNames)

	for _, varName := range varNames {
		evs := missingVars[varName]
		findings = append(findings, schema.Finding{
			ID:           "F-ENV-002",
			Title:        fmt.Sprintf("Compose references env variable that may be undefined: %s", varName),
			Severity:     schema.SeverityMedium,
			Confidence:   0.6,
			Symptom:      fmt.Sprintf("Compose file references environment variable %s which may not be defined", varName),
			Evidence:     evs,
			LikelyCauses: []string{"Variable was not found in collected local env file evidence"},
		})
	}

	return findings
}

func parseComposeRef(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "$") {
		return "", false
	}
	inner := strings.TrimPrefix(raw, "$")
	if strings.HasPrefix(inner, "{") && strings.HasSuffix(inner, "}") {
		inner = inner[1 : len(inner)-1]
	} else {
		// simple $VAR
		return inner, false
	}

	// Check modifiers
	hasDefault := false
	for _, sep := range []string{":-", "-", ":+", "+"} {
		if idx := strings.Index(inner, sep); idx != -1 {
			inner = inner[:idx]
			hasDefault = true
			break
		}
	}
	// Strip error check modifiers but do not mark as having default
	for _, sep := range []string{":?", "?"} {
		if idx := strings.Index(inner, sep); idx != -1 {
			inner = inner[:idx]
			break
		}
	}
	return strings.TrimSpace(inner), hasDefault
}

// gitRules creates findings from git collector evidence.
func (e *M1Engine) gitRules(result schema.CollectorResult) []schema.Finding {
	var findings []schema.Finding
	var trackedEnv []string
	var envIgnored, envExists bool

	for _, ev := range result.Evidence {
		switch ev.Source {
		case "git_tracked_env":
			trackedEnv = riskyTrackedEnvFiles(strings.Split(ev.Value, ", "))
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
			FixHints:     []string{"gitignore-env"},
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
			FixHints:     []string{"gitignore-env"},
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

// hostRuntimeRules joins M1 runtime expectations with M2 host runtime state.
func (e *M1Engine) hostRuntimeRules(result schema.CollectorResult, collectors map[string]schema.CollectorResult) []schema.Finding {
	var findings []schema.Finding

	// Build expected versions from M1 runtime collector
	expected := map[string]string{} // runtime name → expected version
	if m1Runtime, ok := collectors["runtime"]; ok {
		for _, ev := range m1Runtime.Evidence {
			parts := strings.SplitN(ev.Value, " ", 2)
			if len(parts) == 2 {
				name := parts[0]
				// M1 uses "rust" from Cargo.toml, M2 checks "rustc" binary
				if name == "rust" {
					name = "rustc"
				}
				expected[name] = parts[1]
			}
		}
	}

	// Build host actual versions from M2 host_runtime collector
	actual := map[string]string{}   // runtime name → actual version
	paths := map[string]string{}    // runtime name → path
	missing := map[string]bool{}    // runtime name → missing
	managers := map[string]string{} // runtime name → version manager

	for _, ev := range result.Evidence {
		switch {
		case strings.HasSuffix(ev.Source, "_version"):
			rt := strings.TrimSuffix(ev.Source, "_version")
			rt = strings.TrimPrefix(rt, "host_")
			actual[rt] = ev.Value
		case strings.HasSuffix(ev.Source, "_path"):
			rt := strings.TrimSuffix(ev.Source, "_path")
			rt = strings.TrimPrefix(rt, "host_")
			paths[rt] = ev.Value
		case strings.HasSuffix(ev.Source, "_missing"):
			rt := strings.TrimSuffix(ev.Source, "_missing")
			rt = strings.TrimPrefix(rt, "host_")
			missing[rt] = ev.Value == "true"
		case strings.HasSuffix(ev.Source, "_manager"):
			rt := strings.TrimSuffix(ev.Source, "_manager")
			rt = strings.TrimPrefix(rt, "host_")
			managers[rt] = ev.Value
		}
	}

	// Check each expected runtime
	for rt, expVer := range expected {
		if missing[rt] {
			findings = append(findings, schema.Finding{
				ID:         "F-RUNTIME-003",
				Title:      fmt.Sprintf("Required runtime '%s' not found on host", rt),
				Severity:   schema.SeverityHigh,
				Confidence: 0.8,
				Symptom:    fmt.Sprintf("Project expects %s but it is not installed", rt),
				Evidence: []schema.Evidence{
					{Source: "expected_" + rt, Value: expVer},
					{Source: "host_" + rt + "_missing", Value: "true"},
				},
				LikelyCauses: []string{
					"Runtime is not installed or not in PATH",
					"Version manager (nvm, pyenv, etc.) may not be active in this shell",
				},
			})
			continue
		}

		actVer, hasActual := actual[rt]
		if !hasActual || actVer == "" {
			continue // version query failed, no finding
		}

		if !versionsCompatible(expVer, actVer) {
			id := runtimeFindingID(rt)
			findings = append(findings, schema.Finding{
				ID:         id,
				Title:      fmt.Sprintf("%s version mismatch: repo expects %s, host has %s", rt, expVer, actVer),
				Severity:   schema.SeverityMedium,
				Confidence: confidenceForVersion(expVer),
				Symptom:    fmt.Sprintf("Installed %s version does not match project expectation", rt),
				Evidence: []schema.Evidence{
					{Source: "expected_" + rt, Value: expVer},
					{Source: "host_" + rt + "_version", Value: actVer},
					{Source: "host_" + rt + "_path", Value: paths[rt]},
					{Source: "host_" + rt + "_manager", Value: managers[rt]},
				},
				LikelyCauses: []string{
					"Version manager may be using a different version",
					"Project was developed with a different runtime version",
				},
			})
		}
	}

	return findings
}

func runtimeFindingID(rt string) string {
	switch rt {
	case "node":
		return "F-RUNTIME-001"
	case "python":
		return "F-RUNTIME-002"
	case "dotnet":
		return "F-RUNTIME-004"
	case "go":
		return "F-RUNTIME-005"
	case "rustc":
		return "F-RUNTIME-006"
	default:
		return "F-RUNTIME-003"
	}
}

func versionsCompatible(expected, actual string) bool {
	expected = strings.TrimSpace(expected)
	actual = strings.TrimSpace(actual)

	if expected == "lts/*" || expected == "node" || expected == "" {
		return true
	}

	if ok, evaluated := versionExpressionSatisfied(expected, actual); evaluated {
		return ok
	}
	if ok, evaluated := versionExpressionSatisfied(actual, expected); evaluated {
		return ok
	}

	eNorm := normalizeVersion(expected)
	aNorm := normalizeVersion(actual)

	eParts := strings.Split(eNorm, ".")
	aParts := strings.Split(aNorm, ".")

	// Compare up to 2 segments (major.minor), ignoring patch differences
	maxSeg := 2
	if len(eParts) < maxSeg {
		maxSeg = len(eParts)
	}
	for i := 0; i < maxSeg && i < len(aParts); i++ {
		if eParts[i] != aParts[i] {
			return false
		}
	}
	return true
}

func versionExpressionSatisfied(expr, actual string) (bool, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" || !looksLikeVersionExpression(expr) {
		return false, false
	}

	actualParts, ok := parseVersionParts(actual)
	if !ok {
		return false, false
	}

	if strings.HasPrefix(expr, "^") {
		base, ok := parseVersionParts(strings.TrimPrefix(expr, "^"))
		if !ok {
			return false, false
		}
		return compareVersionParts(actualParts, base) >= 0 && compareVersionParts(actualParts, caretUpperBound(base)) < 0, true
	}
	if strings.HasPrefix(expr, "~") && !strings.HasPrefix(expr, "~>") {
		base, ok := parseVersionParts(strings.TrimPrefix(expr, "~"))
		if !ok {
			return false, false
		}
		return compareVersionParts(actualParts, base) >= 0 && compareVersionParts(actualParts, tildeUpperBound(base)) < 0, true
	}

	tokens := strings.Fields(strings.ReplaceAll(expr, ",", " "))
	if len(tokens) == 0 {
		return false, false
	}
	for _, token := range tokens {
		ok, evaluated := versionConstraintSatisfied(token, actualParts)
		if !evaluated || !ok {
			return ok, evaluated
		}
	}
	return true, true
}

func looksLikeVersionExpression(expr string) bool {
	return strings.Contains(expr, " ") ||
		strings.Contains(expr, ",") ||
		strings.HasPrefix(expr, ">") ||
		strings.HasPrefix(expr, "<") ||
		strings.HasPrefix(expr, "^") ||
		strings.HasPrefix(expr, "~") ||
		strings.Contains(expr, ".x") ||
		strings.Contains(expr, ".*")
}

func versionConstraintSatisfied(token string, actualParts []int) (bool, bool) {
	token = strings.TrimSpace(token)
	if token == "" {
		return true, true
	}

	operator := "="
	switch {
	case strings.HasPrefix(token, ">="):
		operator = ">="
		token = strings.TrimSpace(strings.TrimPrefix(token, ">="))
	case strings.HasPrefix(token, "<="):
		operator = "<="
		token = strings.TrimSpace(strings.TrimPrefix(token, "<="))
	case strings.HasPrefix(token, ">"):
		operator = ">"
		token = strings.TrimSpace(strings.TrimPrefix(token, ">"))
	case strings.HasPrefix(token, "<"):
		operator = "<"
		token = strings.TrimSpace(strings.TrimPrefix(token, "<"))
	case strings.HasPrefix(token, "="):
		token = strings.TrimSpace(strings.TrimPrefix(token, "="))
	}

	targetParts, ok := parseVersionParts(token)
	if !ok {
		return false, false
	}
	cmp := compareVersionPartsPrefix(actualParts, targetParts)
	switch operator {
	case ">=":
		return cmp >= 0, true
	case "<=":
		return cmp <= 0, true
	case ">":
		return cmp > 0, true
	case "<":
		return cmp < 0, true
	default:
		return cmp == 0, true
	}
}

func parseVersionParts(v string) ([]int, bool) {
	v = normalizeVersion(v)
	v = strings.TrimSpace(v)
	if v == "" || v == "*" {
		return nil, false
	}
	fields := strings.Split(v, ".")
	parts := make([]int, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		field = strings.TrimRight(field, "xX*")
		if field == "" {
			break
		}
		n, err := strconv.Atoi(field)
		if err != nil {
			return nil, false
		}
		parts = append(parts, n)
	}
	if len(parts) == 0 {
		return nil, false
	}
	return parts, true
}

func compareVersionParts(actual, target []int) int {
	maxLen := len(actual)
	if len(target) > maxLen {
		maxLen = len(target)
	}
	for i := 0; i < maxLen; i++ {
		a := 0
		if i < len(actual) {
			a = actual[i]
		}
		t := 0
		if i < len(target) {
			t = target[i]
		}
		if a < t {
			return -1
		}
		if a > t {
			return 1
		}
	}
	return 0
}

func compareVersionPartsPrefix(actual, target []int) int {
	for i := 0; i < len(target); i++ {
		a := 0
		if i < len(actual) {
			a = actual[i]
		}
		if a < target[i] {
			return -1
		}
		if a > target[i] {
			return 1
		}
	}
	return 0
}

func caretUpperBound(base []int) []int {
	if len(base) == 0 {
		return []int{1}
	}
	upper := append([]int(nil), base...)
	if upper[0] > 0 {
		return []int{upper[0] + 1}
	}
	if len(upper) > 1 {
		return []int{0, upper[1] + 1}
	}
	return []int{1}
}

func tildeUpperBound(base []int) []int {
	if len(base) > 1 {
		return []int{base[0], base[1] + 1}
	}
	return []int{base[0] + 1}
}

func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimPrefix(v, "go")
	// Strip common semver prefixes that appear in .nvmrc / package.json
	for _, prefix := range []string{">=", "<=", "~>", "^", ">", "<", "=", "node", "lts/"} {
		v = strings.TrimPrefix(v, prefix)
	}
	v = strings.TrimSpace(v)
	return v
}

func confidenceForVersion(expected string) float64 {
	if expected == "lts/*" || expected == "node" || !strings.Contains(expected, ".") {
		return 0.5
	}
	return 0.8
}

// diskRules creates findings from disk collector evidence.
func (e *M1Engine) diskRules(result schema.CollectorResult) []schema.Finding {
	var findings []schema.Finding

	var freeBytes, freePct, freeInodesPct float64
	var hasFreeInodesPct bool
	inodesAvailable := true
	for _, ev := range result.Evidence {
		switch ev.Source {
		case "host_disk_free_bytes":
			freeBytes, _ = strconv.ParseFloat(ev.Value, 64)
		case "host_disk_free_pct":
			freePct, _ = strconv.ParseFloat(ev.Value, 64)
		case "host_disk_free_inodes_pct":
			if parsed, err := strconv.ParseFloat(ev.Value, 64); err == nil {
				freeInodesPct = parsed
				hasFreeInodesPct = true
			}
		case "host_disk_inodes_available":
			inodesAvailable = ev.Value != "false"
		}
	}

	giB := 1024.0 * 1024.0 * 1024.0
	inodeCritical := inodesAvailable && hasFreeInodesPct && freeInodesPct < 2.0
	inodeLow := inodesAvailable && hasFreeInodesPct && freeInodesPct < 10.0
	if freeBytes < giB || freePct < 2.0 || inodeCritical {
		findings = append(findings, schema.Finding{
			ID:         "F-DISK-001",
			Title:      "Disk or inode pressure on repo mount",
			Severity:   schema.SeverityMedium,
			Confidence: 0.8,
			Symptom:    "Repo mount is critically low on disk space or inodes",
			Evidence:   result.Evidence,
			LikelyCauses: []string{
				"Build artifacts or caches consuming space",
				"Large dependency trees",
			},
			FixHints: []string{"warn-disk-cleanup"},
		})
	} else if freeBytes < 5*giB || freePct < 10.0 || inodeLow {
		findings = append(findings, schema.Finding{
			ID:         "F-DISK-001",
			Title:      "Disk or inode pressure on repo mount",
			Severity:   schema.SeverityMedium,
			Confidence: 0.7,
			Symptom:    "Repo mount is low on disk space or inodes",
			Evidence:   result.Evidence,
			LikelyCauses: []string{
				"Build artifacts or caches consuming space",
				"Large dependency trees",
			},
			FixHints: []string{"warn-disk-cleanup"},
		})
	}

	return findings
}

func riskyTrackedEnvFiles(files []string) []string {
	var risky []string
	for _, file := range files {
		file = strings.TrimSpace(file)
		if file == "" || isSafeEnvTemplatePath(file) {
			continue
		}
		risky = append(risky, file)
	}
	return risky
}

func isSafeEnvTemplatePath(path string) bool {
	base := path
	if idx := strings.LastIndex(base, "/"); idx != -1 {
		base = base[idx+1:]
	}
	if base == ".env" {
		return false
	}
	if !strings.HasPrefix(base, ".env.") {
		return false
	}
	for _, suffix := range []string{".example", ".sample", ".template", ".dist", ".schema", ".default", ".defaults"} {
		if strings.HasSuffix(base, suffix) {
			return true
		}
	}
	return false
}

// portRules creates findings from port collector evidence.
func (e *M1Engine) portRules(result schema.CollectorResult, collectors map[string]schema.CollectorResult) []schema.Finding {
	var findings []schema.Finding

	// Build set of listening ports
	listening := map[int]bool{}
	for _, ev := range result.Evidence {
		if strings.HasPrefix(ev.Source, "host_listen_port_") {
			if p, err := strconv.Atoi(ev.Value); err == nil {
				listening[p] = true
			}
		}
	}

	// Extract declared host ports from compose evidence
	composePorts := extractComposeHostPorts(collectors)

	for _, port := range composePorts {
		if listening[port] {
			findings = append(findings, schema.Finding{
				ID:         "F-PORT-001",
				Title:      fmt.Sprintf("Declared host port %d already in use", port),
				Severity:   schema.SeverityHigh,
				Confidence: 0.7,
				Symptom:    "A port declared in compose is already listening on the host",
				Evidence: []schema.Evidence{
					{Source: "compose_host_port", Value: strconv.Itoa(port)},
					{Source: "host_listen_port", Value: strconv.Itoa(port)},
				},
				LikelyCauses: []string{
					"Another service is already bound to this port",
					"Previous instance of the service did not shut down cleanly",
				},
				FixHints: []string{"change-compose-port", "stop-service"},
			})
		}
	}

	return findings
}

func extractComposeHostPorts(collectors map[string]schema.CollectorResult) []int {
	var ports []int
	compose, ok := collectors["compose"]
	if !ok {
		return ports
	}
	for _, ev := range compose.Evidence {
		if ev.Source == "compose_host_port" {
			// Value is the host port string (may include IP like "127.0.0.1:8000")
			val := ev.Value
			if strings.Contains(val, ":") {
				// Extract port from "127.0.0.1:8000" style
				parts := strings.Split(val, ":")
				val = parts[len(parts)-1]
			}
			if p, err := strconv.Atoi(val); err == nil {
				ports = append(ports, p)
			}
		}
	}
	return ports
}

// networkRules creates findings from network collector evidence.
func (e *M1Engine) networkRules(result schema.CollectorResult) []schema.Finding {
	var findings []schema.Finding

	var hasProxy, hasNoProxy bool
	for _, ev := range result.Evidence {
		if ev.Source == "host_proxy_env" {
			hasProxy = true
		}
		if ev.Source == "host_no_proxy" {
			hasNoProxy = true
		}
	}

	if hasProxy && !hasNoProxy {
		findings = append(findings, schema.Finding{
			ID:         "F-NET-001",
			Title:      "Proxy env var set but NO_PROXY is empty",
			Severity:   schema.SeverityLow,
			Confidence: 0.5,
			Symptom:    "HTTP proxy is configured without NO_PROXY exclusions",
			Evidence:   result.Evidence,
			LikelyCauses: []string{
				"Proxy may redirect local service traffic unexpectedly",
				"Add localhost, 127.0.0.1 to NO_PROXY if local services fail",
			},
		})
	}

	return findings
}

// systemdRules creates findings from systemd collector evidence.
func (e *M1Engine) systemdRules(result schema.CollectorResult) []schema.Finding {
	var findings []schema.Finding

	for _, ev := range result.Evidence {
		if ev.Source == "host_docker_service" && ev.Value == "inactive" {
			findings = append(findings, schema.Finding{
				ID:         "F-SVC-001",
				Title:      "Docker service inactive but repo expects Docker",
				Severity:   schema.SeverityMedium,
				Confidence: 0.7,
				Symptom:    "Repo contains Docker/Compose files but the Docker service is not running",
				Evidence:   result.Evidence,
				LikelyCauses: []string{
					"Docker daemon is not started",
					"User is not in the docker group",
				},
			})
		}
	}

	return findings
}

// permissionRules creates findings from permission collector evidence.
func (e *M1Engine) permissionRules(result schema.CollectorResult) []schema.Finding {
	var findings []schema.Finding

	for _, ev := range result.Evidence {
		if ev.Source == "host_script_not_executable" {
			findings = append(findings, schema.Finding{
				ID:         "F-FS-001",
				Title:      fmt.Sprintf("Script missing executable bit: %s", ev.Value),
				Severity:   schema.SeverityMedium,
				Confidence: 0.8,
				Symptom:    "A referenced script cannot be executed due to missing permissions",
				Evidence:   []schema.Evidence{ev},
				LikelyCauses: []string{
					"File was created without execute permissions",
					"Permissions were reset during file copy or extraction",
				},
				FixHints: []string{"chmod-script"},
			})
		}
		if ev.Source == "host_file_root_owned" {
			findings = append(findings, schema.Finding{
				ID:         "F-PERM-002",
				Title:      fmt.Sprintf("File owned by root: %s", ev.Value),
				Severity:   schema.SeverityLow,
				Confidence: 0.6,
				Symptom:    "A repo-relevant file is owned by root",
				Evidence:   []schema.Evidence{ev},
				LikelyCauses: []string{
					"Possibly created by prior sudo command",
					"File was created as root and ownership was not transferred",
				},
			})
		}
	}

	return findings
}

func (e *M1Engine) securityRules(result schema.CollectorResult) []schema.Finding {
	var selinuxEvidence []schema.Evidence
	var appArmorEvidence []schema.Evidence
	for _, ev := range result.Evidence {
		switch ev.Source {
		case "selinux_denial":
			selinuxEvidence = append(selinuxEvidence, ev)
		case "apparmor_denial":
			appArmorEvidence = append(appArmorEvidence, ev)
		}
	}

	var findings []schema.Finding
	if len(selinuxEvidence) > 0 {
		likelyCauses := []string{
			"Bind mount or workspace path may have an SELinux label mismatch",
			"Container volume may need an explicit shared or private SELinux relabel",
			"Process domain is not allowed to access the target path",
		}
		fixHints := []string{"inspect-selinux-context"}
		if evidenceContainsValue(selinuxEvidence, "container_label_hint=mount_relabel_z_or_Z") {
			likelyCauses = append([]string{"Container bind mount is missing an SELinux shared/private relabel such as :z or :Z"}, likelyCauses...)
			fixHints = append(fixHints, "relabel-container-volume")
		}
		findings = append(findings, schema.Finding{
			ID:           "F-SEC-SELINUX-001",
			Title:        "SELinux denial likely blocking project access",
			Severity:     schema.SeverityMedium,
			Confidence:   0.7,
			Symptom:      "Kernel audit logs show SELinux denied a file or process operation",
			Evidence:     selinuxEvidence,
			LikelyCauses: likelyCauses,
			FixHints:     fixHints,
		})
	}
	if len(appArmorEvidence) > 0 {
		likelyCauses := []string{
			"Container or process profile denies the requested operation",
			"Mounted workspace path is outside the allowed profile paths",
			"Service profile needs adjustment or a less restrictive local dev profile",
		}
		fixHints := []string{"inspect-apparmor-denial"}
		if evidenceContainsValue(appArmorEvidence, "profile=docker-default") {
			likelyCauses = append([]string{"Docker default AppArmor profile denied access to the mounted project path"}, likelyCauses...)
			fixHints = append(fixHints, "review-apparmor-profile")
		}
		findings = append(findings, schema.Finding{
			ID:           "F-SEC-APPARMOR-001",
			Title:        "AppArmor denial likely blocking project access",
			Severity:     schema.SeverityMedium,
			Confidence:   0.7,
			Symptom:      "Kernel audit logs show AppArmor denied a file or process operation",
			Evidence:     appArmorEvidence,
			LikelyCauses: likelyCauses,
			FixHints:     fixHints,
		})
	}
	return findings
}

func evidenceContainsValue(evidence []schema.Evidence, needle string) bool {
	for _, ev := range evidence {
		if strings.Contains(ev.Value, needle) {
			return true
		}
	}
	return false
}

// dockerRules creates findings from docker collector evidence.
func (e *M1Engine) dockerRules(result schema.CollectorResult, collectors map[string]schema.CollectorResult) []schema.Finding {
	var findings []schema.Finding

	hasPermissionDenied := false
	hasComposePlugin := false
	for _, ev := range result.Evidence {
		if ev.Source == "docker_socket_permission_denied" {
			hasPermissionDenied = true
		}
		if ev.Source == "docker_compose_plugin" && ev.Value == "available" {
			hasComposePlugin = true
		}
	}

	if result.Status == schema.CollectorUnavailable {
		if hasPermissionDenied {
			findings = append(findings, schema.Finding{
				ID:         "F-DOCKER-002",
				Title:      "Docker socket permission denied",
				Severity:   schema.SeverityMedium,
				Confidence: 0.7,
				Symptom:    "Cannot access Docker daemon socket due to permission restrictions",
				Evidence:   result.Evidence,
				LikelyCauses: []string{
					"Current user may not be in the docker group",
					"Docker daemon may be running with restricted socket permissions",
					"Rootless Docker may require different socket path",
				},
				FixHints: []string{"suggest-docker-group"},
			})
		} else {
			findings = append(findings, schema.Finding{
				ID:         "F-DOCKER-001",
				Title:      "Docker daemon inactive or inaccessible",
				Severity:   schema.SeverityHigh,
				Confidence: 0.8,
				Symptom:    "Docker daemon is not running or is unreachable",
				Evidence:   result.Evidence,
				LikelyCauses: []string{
					"Docker service is not started",
					"Docker daemon is misconfigured",
				},
				FixHints: []string{"suggest-docker-group"},
			})
		}
	}

	// Only emit F-DOCKER-003 if repo has compose/devcontainer signals
	repoHasCompose := false
	if compose, ok := collectors["compose"]; ok {
		for _, ev := range compose.Evidence {
			if ev.Source == "compose" {
				repoHasCompose = true
				break
			}
		}
	}
	if !hasComposePlugin && repoHasCompose {
		for _, ev := range result.Evidence {
			if ev.Source == "docker_compose_plugin" && (ev.Value == "missing" || ev.Value == "legacy_docker-compose") {
				findings = append(findings, schema.Finding{
					ID:         "F-DOCKER-003",
					Title:      "Docker Compose plugin missing",
					Severity:   schema.SeverityMedium,
					Confidence: 0.6,
					Symptom:    "Repo has Compose files but Docker Compose plugin is not available",
					Evidence:   result.Evidence,
					LikelyCauses: []string{
						"Docker Compose plugin is not installed",
						"Legacy docker-compose binary may be available as fallback",
					},
				})
				break
			}
		}
	}

	return findings
}

// podmanRules creates findings from podman collector evidence.
func (e *M1Engine) podmanRules(result schema.CollectorResult) []schema.Finding {
	var findings []schema.Finding

	if result.Status == schema.CollectorUnavailable {
		likelyCauses := []string{
			"Podman is not installed",
			"Podman service is not running",
		}
		if evidenceSourceValue(result.Evidence, "podman_runtime_dir_error", "true") {
			likelyCauses = append([]string{"Rootless Podman runtime directory under /run/user is missing or inaccessible"}, likelyCauses...)
		}
		findings = append(findings, schema.Finding{
			ID:           "F-PODMAN-001",
			Title:        "Podman unavailable (repo expects containers)",
			Severity:     schema.SeverityMedium,
			Confidence:   0.7,
			Symptom:      "Repo has container signals but Podman is not accessible",
			Evidence:     result.Evidence,
			LikelyCauses: likelyCauses,
		})
	}

	return findings
}

func evidenceSourceValue(evidence []schema.Evidence, source, value string) bool {
	for _, ev := range evidence {
		if ev.Source == source && ev.Value == value {
			return true
		}
	}
	return false
}

// composeStatusRules creates findings from compose_status collector evidence.
func (e *M1Engine) composeStatusRules(result schema.CollectorResult, collectors map[string]schema.CollectorResult) []schema.Finding {
	var findings []schema.Finding

	// Service not running
	for _, ev := range result.Evidence {
		if strings.HasSuffix(ev.Source, "_status") {
			serviceName := strings.TrimPrefix(ev.Source, "compose_service_")
			serviceName = strings.TrimSuffix(serviceName, "_status")
			if serviceName != "" {
				status := ev.Value
				if status == "exited" || status == "dead" || status == "restarting" {
					findings = append(findings, schema.Finding{
						ID:         "F-CONTAINER-001",
						Title:      fmt.Sprintf("Compose service '%s' is not running", serviceName),
						Severity:   schema.SeverityHigh,
						Confidence: 0.8,
						Symptom:    fmt.Sprintf("Service '%s' is in state '%s'", serviceName, status),
						Evidence:   []schema.Evidence{ev},
						LikelyCauses: []string{
							"Service may have crashed or failed to start",
							"Dependent services may be unavailable",
						},
						FixHints: []string{"compose-up", "inspect-service"},
					})
				}
			}
		}
	}

	// Unhealthy services
	for _, ev := range result.Evidence {
		if strings.HasSuffix(ev.Source, "_health") {
			serviceName := strings.TrimPrefix(ev.Source, "compose_service_")
			serviceName = strings.TrimSuffix(serviceName, "_health")
			if serviceName != "" {
				if ev.Value == "unhealthy" {
					findings = append(findings, schema.Finding{
						ID:         "F-CONTAINER-001",
						Title:      fmt.Sprintf("Compose service '%s' is unhealthy", serviceName),
						Severity:   schema.SeverityHigh,
						Confidence: 0.8,
						Symptom:    fmt.Sprintf("Service '%s' healthcheck is failing", serviceName),
						Evidence:   []schema.Evidence{ev},
						LikelyCauses: []string{
							"Service dependencies may be unavailable",
							"Healthcheck configuration may be too strict",
						},
						FixHints: []string{"inspect-service"},
					})
				}
			}
		}
	}

	// Bind mount source missing
	for _, ev := range result.Evidence {
		if strings.HasSuffix(ev.Source, "_bind_mount_source") {
			serviceName := strings.TrimPrefix(ev.Source, "compose_service_")
			serviceName = strings.TrimSuffix(serviceName, "_bind_mount_source")
			if serviceName != "" {
				if strings.HasSuffix(ev.Value, "=false") {
					sourcePath := strings.TrimSuffix(ev.Value, "=false")
					findings = append(findings, schema.Finding{
						ID:         "F-CONTAINER-003",
						Title:      fmt.Sprintf("Bind mount source missing or unreadable for service '%s'", serviceName),
						Severity:   schema.SeverityMedium,
						Confidence: 0.7,
						Symptom:    fmt.Sprintf("Host path '%s' does not exist or is not readable", sourcePath),
						Evidence:   []schema.Evidence{ev},
						LikelyCauses: []string{
							"Path was removed after compose file was written",
							"Path requires different permissions",
						},
					})
				}
			}
		}
	}

	return findings
}

// reproRules creates findings from repro collector evidence.
func (e *M1Engine) reproRules(result schema.CollectorResult) []schema.Finding {
	var findings []schema.Finding

	if result.Status == schema.CollectorTimeout {
		findings = append(findings, schema.Finding{
			ID:         "F-REPRO-009",
			Title:      "Command timed out during reproduction",
			Severity:   schema.SeverityHigh,
			Confidence: 0.9,
			Symptom:    "The repro command exceeded its timeout budget",
			Evidence:   result.Evidence,
			LikelyCauses: []string{
				"Command is slower than expected",
				"Command may be waiting for input or a network resource",
			},
		})
		return findings
	}

	var exitCode int
	var exitCodeSet bool
	var hasClassification bool
	for _, ev := range result.Evidence {
		if ev.Source == "repro_exit_code" {
			if n, err := fmt.Sscanf(ev.Value, "%d", &exitCode); err == nil && n == 1 {
				exitCodeSet = true
			}
		}
		if ev.Source == "repro_classification" {
			hasClassification = true
			kind := ev.Value
			var id, title string
			var severity schema.Severity
			var symptom string
			switch kind {
			case "permission_denied":
				id = "F-REPRO-002"
				title = "Permission denied during command execution"
				severity = schema.SeverityMedium
				symptom = "Command output indicates permission was denied"
			case "missing_file":
				id = "F-REPRO-003"
				title = "Missing file or command not found"
				severity = schema.SeverityMedium
				symptom = "Command output indicates a required file or command is missing"
			case "address_in_use":
				id = "F-REPRO-004"
				title = "Address already in use (port conflict)"
				severity = schema.SeverityMedium
				symptom = "Command output indicates a port binding conflict"
			case "connection_refused":
				id = "F-REPRO-005"
				title = "Connection refused or network unreachable"
				severity = schema.SeverityMedium
				symptom = "Command output indicates a connection was refused"
			case "runtime_version_failure":
				id = "F-REPRO-006"
				title = "Runtime version failure during command execution"
				severity = schema.SeverityMedium
				symptom = "Command output indicates the active runtime version does not satisfy the project"
			case "dependency_failure":
				id = "F-REPRO-007"
				title = "Dependency resolver failure"
				severity = schema.SeverityMedium
				symptom = "Command output indicates a dependency resolution failure"
			case "compose_config_error":
				id = "F-REPRO-008"
				title = "Compose interpolation or config error"
				severity = schema.SeverityMedium
				symptom = "Command output indicates a Compose configuration error"
			default:
				continue
			}
			findings = append(findings, schema.Finding{
				ID:         id,
				Title:      title,
				Severity:   severity,
				Confidence: 0.7,
				Symptom:    symptom,
				Evidence:   []schema.Evidence{ev},
			})
		}
	}

	if exitCodeSet && exitCode != 0 && !hasClassification {
		findings = append(findings, schema.Finding{
			ID:         "F-REPRO-001",
			Title:      "Command exited with non-zero code",
			Severity:   schema.SeverityHigh,
			Confidence: 0.8,
			Symptom:    fmt.Sprintf("Command exited with code %d", exitCode),
			Evidence:   result.Evidence,
		})
	}

	return findings
}
