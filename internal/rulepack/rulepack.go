package rulepack

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type Pack struct {
	ID          string `json:"id" yaml:"id"`
	Name        string `json:"name,omitempty" yaml:"name,omitempty"`
	Version     string `json:"version" yaml:"version"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
	Rules       []Rule `json:"rules" yaml:"rules"`
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
		{ID: "core", Name: "Core Linux diagnostics", Version: "0.1", Description: "Repo, env, runtime, host, service, and filesystem rules"},
		{ID: "containers", Name: "Docker and Podman diagnostics", Version: "0.1", Description: "Container runtime, Compose, SELinux, and AppArmor rules"},
		{ID: "gpu-ml", Name: "GPU and ML diagnostics", Version: "0.1", Description: "NVIDIA, CUDA, Python ML, cache, and container GPU rules"},
		{ID: "ci", Name: "CI/local parity diagnostics", Version: "0.1", Description: "GitHub Actions, GitLab CI, local parity, annotation, and artifact rules"},
		{ID: "agent-safety", Name: "Agent safety diagnostics", Version: "0.1", Description: "Untrusted-context and prompt-injection evidence rules"},
	}
}

func Validate(data []byte) (Pack, ValidationResult) {
	var pack Pack
	result := ValidationResult{Valid: true}
	if err := yaml.Unmarshal(data, &pack); err != nil {
		return pack, ValidationResult{Valid: false, Errors: []string{fmt.Sprintf("parse rule pack: %v", err)}}
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
