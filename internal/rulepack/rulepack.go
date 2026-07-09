package rulepack

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cuelang.org/go/cue"
	"cuelang.org/go/cue/cuecontext"
	cueerrors "cuelang.org/go/cue/errors"
	cueyaml "cuelang.org/go/encoding/yaml"
	"github.com/meedoomostafa/devdiag/internal/schema"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"gopkg.in/yaml.v3"
)

type Pack struct {
	SchemaVersion string        `json:"schema_version,omitempty" yaml:"schema_version"`
	ID            string        `json:"id" yaml:"id"`
	Name          string        `json:"name,omitempty" yaml:"name,omitempty"`
	Version       string        `json:"version" yaml:"version"`
	Description   string        `json:"description,omitempty" yaml:"description,omitempty"`
	Engine        string        `json:"engine,omitempty" yaml:"engine"`
	Entrypoint    string        `json:"entrypoint,omitempty" yaml:"entrypoint"`
	PolicyFiles   []string      `json:"policy_files,omitempty" yaml:"policy_files"`
	Publisher     string        `json:"publisher,omitempty" yaml:"publisher"`
	License       string        `json:"license,omitempty" yaml:"license"`
	Homepage      string        `json:"homepage,omitempty" yaml:"homepage"`
	Compatibility Compatibility `json:"compatibility,omitempty" yaml:"compatibility"`
	Tags          []string      `json:"tags,omitempty" yaml:"tags"`
	Rules         []Rule        `json:"rules" yaml:"rules"`
}

type Compatibility struct {
	DevDiagMinVersion string `json:"devdiag_min_version,omitempty" yaml:"devdiag_min_version"`
}

type Rule struct {
	ID       string `json:"id" yaml:"id"`
	Severity string `json:"severity,omitempty" yaml:"severity,omitempty"`
	Enabled  *bool  `json:"enabled,omitempty" yaml:"enabled,omitempty"`
}

type ValidationResult struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors,omitempty"`
}

func BuiltInPacks() []Pack {
	return []Pack{
		{SchemaVersion: "1", ID: "core", Name: "Core Linux diagnostics", Version: "0.1", Engine: "go", Description: "Repo, env, runtime, host, service, and filesystem rules"},
		{SchemaVersion: "1", ID: "containers", Name: "Docker and Podman diagnostics", Version: "0.1", Engine: "go", Description: "Container runtime, Compose, SELinux, and AppArmor rules"},
		{SchemaVersion: "1", ID: "gpu-ml", Name: "GPU and ML diagnostics", Version: "0.1", Engine: "go", Description: "NVIDIA, CUDA, Python ML, cache, and container GPU rules"},
		{SchemaVersion: "1", ID: "ci", Name: "CI/local parity diagnostics", Version: "0.1", Engine: "go", Description: "GitHub Actions, GitLab CI, local parity, annotation, and artifact rules"},
		{SchemaVersion: "1", ID: "agent-safety", Name: "Agent safety diagnostics", Version: "0.1", Engine: "go", Description: "Untrusted-context and prompt-injection evidence rules"},
	}
}

const packCueSchema = `
#Rule: {
	id: string
	severity?: "info" | "low" | "medium" | "high" | "critical"
	enabled?: bool
}
#Pack: {
	schema_version?: string
	id: string
	name?: string
	version: string | number
	description?: string
	engine?: "go" | "rego"
	entrypoint?: string
	policy_files?: [...string]
	publisher?: string
	license?: string
	homepage?: string
	compatibility?: {
		devdiag_min_version?: string
	}
	tags?: [...string]
	rules: [...#Rule]
}
`

func Validate(data []byte) (Pack, ValidationResult) {
	var pack Pack
	result := ValidationResult{Valid: true}
	file, cueErr := cueyaml.Extract("rulepack.yaml", data)
	if cueErr != nil {
		return pack, ValidationResult{Valid: false, Errors: []string{fmt.Sprintf("parse rule pack: %v", cueErr)}}
	}
	ctx := cuecontext.New()
	cueSchema := ctx.CompileString(packCueSchema)
	if err := cueSchema.Err(); err != nil {
		return pack, ValidationResult{Valid: false, Errors: []string{fmt.Sprintf("compile rule pack schema: %v", err)}}
	}
	value := ctx.BuildFile(file)
	if err := value.Err(); err != nil {
		return pack, ValidationResult{Valid: false, Errors: []string{fmt.Sprintf("parse rule pack: %v", err)}}
	}
	if err := cueSchema.LookupPath(cue.ParsePath("#Pack")).Unify(value).Validate(cue.Concrete(true), cue.Final()); err != nil {
		result.Errors = append(result.Errors, splitCUEError(err)...)
	}
	if err := yaml.Unmarshal(data, &pack); err != nil {
		return pack, ValidationResult{Valid: false, Errors: []string{fmt.Sprintf("parse rule pack: %v", err)}}
	}
	if pack.Engine == "" {
		pack.Engine = "go"
	}
	if strings.TrimSpace(pack.ID) == "" {
		result.Errors = append(result.Errors, "id is required")
	}
	if strings.TrimSpace(pack.Version) == "" {
		result.Errors = append(result.Errors, "version is required")
	}
	if len(pack.Rules) == 0 {
		result.Errors = append(result.Errors, "at least one rule is required")
	}
	seenRuleIDs := make(map[string]struct{}, len(pack.Rules))
	for i, rule := range pack.Rules {
		ruleID := strings.TrimSpace(rule.ID)
		if ruleID == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("rules[%d].id is required", i))
		} else if _, ok := seenRuleIDs[ruleID]; ok {
			result.Errors = append(result.Errors, fmt.Sprintf("rules[%d].id %q is duplicated", i, ruleID))
		} else {
			seenRuleIDs[ruleID] = struct{}{}
		}
		if rule.Severity != "" && !validSeverity(rule.Severity) {
			result.Errors = append(result.Errors, fmt.Sprintf("rules[%d].severity %q is invalid", i, rule.Severity))
		}
	}
	switch pack.Engine {
	case "go":
		if len(pack.PolicyFiles) > 0 || strings.TrimSpace(pack.Entrypoint) != "" {
			result.Errors = append(result.Errors, "go rule packs must not define entrypoint or policy_files")
		}
	case "rego":
		if strings.TrimSpace(pack.Entrypoint) == "" {
			result.Errors = append(result.Errors, "rego rule packs require entrypoint")
		}
		if len(pack.PolicyFiles) == 0 {
			result.Errors = append(result.Errors, "rego rule packs require policy_files")
		}
	default:
		result.Errors = append(result.Errors, fmt.Sprintf("unsupported engine %q", pack.Engine))
	}
	for _, policyFile := range pack.PolicyFiles {
		if strings.TrimSpace(policyFile) == "" || filepath.IsAbs(policyFile) || strings.Contains(policyFile, "..") {
			result.Errors = append(result.Errors, fmt.Sprintf("policy file %q is unsafe", policyFile))
		}
	}
	result.Valid = len(result.Errors) == 0
	return pack, result
}

func validSeverity(v string) bool {
	switch v {
	case "info", "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}

type RegoEvaluationResult struct {
	Valid    bool             `json:"valid"`
	Errors   []string         `json:"errors,omitempty"`
	Findings []schema.Finding `json:"findings,omitempty"`
	Pack     Pack             `json:"pack,omitempty"`
}

// regoEvalTimeout bounds third-party Rego policy evaluation so a
// pathological rule pack cannot hang a scan indefinitely.
var regoEvalTimeout = 10 * time.Second

func EvaluateRegoFile(ctx context.Context, packPath string, input any) RegoEvaluationResult {
	data, err := os.ReadFile(packPath)
	if err != nil {
		return RegoEvaluationResult{Valid: false, Errors: []string{fmt.Sprintf("read rule pack: %v", err)}}
	}
	pack, validation := Validate(data)
	result := RegoEvaluationResult{Valid: validation.Valid, Errors: validation.Errors, Pack: pack}
	if !validation.Valid {
		return result
	}
	if pack.Engine != "rego" {
		result.Valid = false
		result.Errors = append(result.Errors, "scan --rule-pack currently evaluates engine: rego packs only")
		return result
	}

	dir := filepath.Dir(packPath)
	options := []func(*rego.Rego){rego.Query(pack.Entrypoint), rego.Input(input), rego.Capabilities(safeRegoCapabilities())}
	for _, name := range pack.PolicyFiles {
		content, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("read policy %s: %v", name, err))
			return result
		}
		if forbidden := forbiddenRegoToken(string(content)); forbidden != "" {
			result.Valid = false
			result.Errors = append(result.Errors, fmt.Sprintf("policy %s uses unsupported token %q", name, forbidden))
			return result
		}
		options = append(options, rego.Module(name, string(content)))
	}
	evalCtx, cancel := context.WithTimeout(ctx, regoEvalTimeout)
	defer cancel()
	rs, err := rego.New(options...).Eval(evalCtx)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, fmt.Sprintf("evaluate rego: %v", err))
		return result
	}
	findings, err := decodeFindingCandidates(rs)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, err.Error())
		return result
	}
	result.Findings = findings
	return result
}

func forbiddenRegoToken(policy string) string {
	for _, token := range []string{"http.send", "net.lookup_ip_addr", "opa.runtime"} {
		if strings.Contains(policy, token) {
			return token
		}
	}
	return ""
}

func safeRegoCapabilities() *ast.Capabilities {
	base := ast.CapabilitiesForThisVersion()
	caps := *base
	blocked := map[string]struct{}{
		"http.send":          {},
		"net.lookup_ip_addr": {},
		"opa.runtime":        {},
	}
	caps.Builtins = make([]*ast.Builtin, 0, len(base.Builtins))
	for _, builtin := range base.Builtins {
		if _, ok := blocked[builtin.Name]; ok || builtin.Nondeterministic {
			continue
		}
		caps.Builtins = append(caps.Builtins, builtin)
	}
	caps.AllowNet = []string{}
	return &caps
}

func decodeFindingCandidates(rs rego.ResultSet) ([]schema.Finding, error) {
	var values []any
	for _, result := range rs {
		for _, expression := range result.Expressions {
			values = append(values, expression.Value)
		}
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	var nested []any
	if err := json.Unmarshal(raw, &nested); err != nil {
		return nil, err
	}
	var findings []schema.Finding
	for _, item := range flattenFindingValues(nested) {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("rego output must contain finding objects")
		}
		id, _ := m["id"].(string)
		title, _ := m["title"].(string)
		severity, _ := m["severity"].(string)
		if strings.TrimSpace(id) == "" || strings.TrimSpace(title) == "" || !validSeverity(severity) {
			return nil, fmt.Errorf("rego finding candidates require id, title, and valid severity")
		}
		finding := schema.Finding{
			ID:              id,
			Title:           title,
			Severity:        schema.Severity(severity),
			Confidence:      numberValue(m["confidence"], 0.7),
			Symptom:         stringValue(m["symptom"]),
			RedactionStatus: "safe",
		}
		findings = append(findings, finding)
	}
	return findings, nil
}

func flattenFindingValues(values []any) []any {
	var out []any
	for _, value := range values {
		switch typed := value.(type) {
		case []any:
			out = append(out, flattenFindingValues(typed)...)
		default:
			out = append(out, typed)
		}
	}
	return out
}

func numberValue(value any, fallback float64) float64 {
	switch typed := value.(type) {
	case float64:
		return typed
	case int:
		return float64(typed)
	default:
		return fallback
	}
}

func stringValue(value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	return ""
}

func splitCUEError(err error) []string {
	if err == nil {
		return nil
	}
	var out []string
	details := cueerrors.Details(err, nil)
	if strings.TrimSpace(details) == "" {
		details = err.Error()
	}
	for _, line := range strings.Split(details, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		out = append(out, err.Error())
	}
	return out
}
