package config

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/configschema"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Collector reads DevDiag project configuration without exposing secret values.
type Collector struct {
	Root string
}

func (c *Collector) Name() string {
	return "config"
}

func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	root := c.Root
	if root == "" {
		root = "."
	}
	path, name, ok := findConfigFile(root)
	if !ok {
		return schema.CollectorResult{Name: c.Name(), Status: schema.CollectorOK}, nil
	}
	select {
	case <-ctx.Done():
		return schema.CollectorResult{Name: c.Name(), Status: schema.CollectorTimeout, Partial: true, Notes: []string{"config collection canceled"}}, nil
	default:
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return schema.CollectorResult{
			Name:   c.Name(),
			Status: schema.CollectorPartial,
			Notes:  []string{fmt.Sprintf("failed to read %s: %v", name, err)},
		}, nil
	}
	validation := configschema.ValidateYAML(data)
	if !validation.Valid {
		return schema.CollectorResult{
			Name:     c.Name(),
			Status:   schema.CollectorPartial,
			Partial:  true,
			Evidence: []schema.Evidence{{Source: "devdiag_config_path", Value: name}},
			Notes:    validation.Errors,
		}, nil
	}
	cfg := validation.Config

	evidence := []schema.Evidence{{Source: "devdiag_config_path", Value: name}}
	for _, key := range cleanKeys(cfg.CI.Env.IgnoreMissingLocal) {
		evidence = append(evidence, schema.Evidence{Source: "devdiag_ci_env_ignore_missing_local", Value: key})
	}
	for _, key := range cleanKeys(cfg.CI.Env.IgnoreMissingCI) {
		evidence = append(evidence, schema.Evidence{Source: "devdiag_ci_env_ignore_missing_ci", Value: key})
	}
	if failSeverity := strings.TrimSpace(cfg.Policy.FailSeverity); failSeverity != "" {
		if !validFailSeverity(failSeverity) {
			return schema.CollectorResult{
				Name:     c.Name(),
				Status:   schema.CollectorPartial,
				Partial:  true,
				Evidence: evidence,
				Notes:    []string{fmt.Sprintf("invalid policy.fail_severity %q in %s", failSeverity, name)},
			}, nil
		}
		evidence = append(evidence, schema.Evidence{Source: "devdiag_policy_fail_severity", Value: failSeverity})
	}
	return schema.CollectorResult{Name: c.Name(), Status: schema.CollectorOK, Evidence: evidence}, nil
}

func findConfigFile(root string) (path, name string, ok bool) {
	for _, candidate := range []string{"devdiag.yaml", "devdiag.yml", ".devdiag.yml", ".devdiag.yaml"} {
		path := filepath.Join(root, candidate)
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path, candidate, true
		}
	}
	return "", "", false
}

func cleanKeys(values []string) []string {
	seen := make(map[string]bool, len(values))
	keys := make([]string, 0, len(values))
	for _, value := range values {
		key := strings.TrimSpace(value)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		keys = append(keys, key)
	}
	return keys
}

func validFailSeverity(v string) bool {
	switch v {
	case "off", "info", "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}
