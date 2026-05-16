package env

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Collector reads .env files and produces evidence about env configuration.
type Collector struct {
	Root string
}

func (c *Collector) Name() string {
	return "env"
}

func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	root := c.Root
	if root == "" {
		root = "."
	}

	evidence := []schema.Evidence{}
	notes := []string{}

	envExamplePath := filepath.Join(root, ".env.example")
	envPath := filepath.Join(root, ".env")
	envLocalPath := filepath.Join(root, ".env.local")

	exampleKeys, exampleErr := parseEnvFileKeys(envExamplePath)
	if exampleErr == nil && len(exampleKeys) > 0 {
		evidence = append(evidence, schema.Evidence{Source: ".env.example", Value: "keys: " + strings.Join(exampleKeys, ", ")})
	}

	envKeys, envErr := parseEnvFileKeys(envPath)
	if envErr == nil && len(envKeys) > 0 {
		evidence = append(evidence, schema.Evidence{Source: ".env", Value: "keys: " + strings.Join(envKeys, ", ")})
	} else if os.IsNotExist(envErr) {
		evidence = append(evidence, schema.Evidence{Source: ".env", Value: "missing"})
	}

	localKeys, localErr := parseEnvFileKeys(envLocalPath)
	if localErr == nil && len(localKeys) > 0 {
		evidence = append(evidence, schema.Evidence{Source: ".env.local", Value: "keys: " + strings.Join(localKeys, ", ")})
	}

	// Missing keys: present in .env.example but not in .env
	if exampleErr == nil && envErr == nil {
		missing := diffKeys(exampleKeys, envKeys)
		if len(missing) > 0 {
			evidence = append(evidence, schema.Evidence{Source: "missing_keys", Value: strings.Join(missing, ", ")})
		}
	}

	// Missing keys from .env.local too
	if localErr == nil {
		missingLocal := diffKeys(exampleKeys, localKeys)
		if len(missingLocal) > 0 {
			evidence = append(evidence, schema.Evidence{Source: "missing_local_keys", Value: strings.Join(missingLocal, ", ")})
		}
	}

	return schema.CollectorResult{
		Name:     c.Name(),
		Status:   schema.CollectorOK,
		Evidence: evidence,
		Notes:    notes,
	}, nil
}

// parseEnvFileKeys conservatively parses .env files, returning only keys.
// Supports: KEY=value, export KEY=value, quoted values, comments, empty values.
// Does NOT expand shell variables or interpret command substitutions.
func parseEnvFileKeys(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var keys []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key := parseEnvLineKey(line)
		if key != "" {
			keys = append(keys, key)
		}
	}
	return keys, scanner.Err()
}

func parseEnvLineKey(line string) string {
	// Handle export prefix
	line = strings.TrimPrefix(line, "export ")

	// Find the first = that isn't inside quotes
	// We do a simple parse: find first unquoted =
	inSingle := false
	inDouble := false
	for i, ch := range line {
		switch ch {
		case '=':
			if !inSingle && !inDouble {
				return strings.TrimSpace(line[:i])
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		}
	}
	return "" // No = found, invalid line
}

func diffKeys(a, b []string) []string {
	m := make(map[string]bool)
	for _, k := range b {
		m[k] = true
	}
	var missing []string
	for _, k := range a {
		if !m[k] {
			missing = append(missing, k)
		}
	}
	return missing
}
