package env

import (
	"bufio"
	"context"
	"fmt"
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

	var totalIgnored int

	exampleKeys, exampleIgnored, exampleErr := parseEnvFileKeys(envExamplePath)
	if exampleErr == nil {
		totalIgnored += exampleIgnored
		if len(exampleKeys) > 0 {
			evidence = append(evidence, schema.Evidence{Source: ".env.example", Value: "keys: " + strings.Join(exampleKeys, ", ")})
		}
	}

	envKeys, envIgnored, envErr := parseEnvFileKeys(envPath)
	if envErr == nil {
		totalIgnored += envIgnored
		if len(envKeys) > 0 {
			evidence = append(evidence, schema.Evidence{Source: ".env", Value: "keys: " + strings.Join(envKeys, ", ")})
		}
	} else if os.IsNotExist(envErr) {
		evidence = append(evidence, schema.Evidence{Source: ".env", Value: "missing"})
	}

	localKeys, localIgnored, localErr := parseEnvFileKeys(envLocalPath)
	if localErr == nil {
		totalIgnored += localIgnored
		if len(localKeys) > 0 {
			evidence = append(evidence, schema.Evidence{Source: ".env.local", Value: "keys: " + strings.Join(localKeys, ", ")})
		}
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

	if totalIgnored > 0 {
		notes = append(notes, fmt.Sprintf("ignored %d invalid lines", totalIgnored))
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
func parseEnvFileKeys(path string) ([]string, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	var keys []string
	var ignoredLinesCount int
	inSingleQuote := false
	inDoubleQuote := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// If we are currently in a multi-line quote, scan the line to see if the quote ends
		if inSingleQuote || inDoubleQuote {
			for i := 0; i < len(line); i++ {
				ch := line[i]
				if inDoubleQuote {
					if ch == '"' && (i == 0 || line[i-1] != '\\') {
						inDoubleQuote = false
					}
				} else if inSingleQuote {
					if ch == '\'' && (i == 0 || line[i-1] != '\\') {
						inSingleQuote = false
					}
				} else {
					if ch == '"' {
						inDoubleQuote = true
					} else if ch == '\'' {
						inSingleQuote = true
					}
				}
			}
			continue
		}

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check for export prefix and strip
		trimmedLine := line
		if strings.HasPrefix(trimmedLine, "export ") {
			trimmedLine = strings.TrimSpace(strings.TrimPrefix(trimmedLine, "export "))
		}

		// Find the first unquoted equal sign or colon
		var keyPart string
		var valPart string
		hasDelimiter := false
		inS := false
		inD := false

		for i := 0; i < len(trimmedLine); i++ {
			ch := trimmedLine[i]
			if inD {
				if ch == '"' && (i == 0 || trimmedLine[i-1] != '\\') {
					inD = false
				}
			} else if inS {
				if ch == '\'' && (i == 0 || trimmedLine[i-1] != '\\') {
					inS = false
				}
			} else {
				if ch == '=' || ch == ':' {
					keyPart = strings.TrimSpace(trimmedLine[:i])
					valPart = trimmedLine[i+1:]
					hasDelimiter = true
					break
				} else if ch == '"' {
					inD = true
				} else if ch == '\'' {
					inS = true
				}
			}
		}

		if !hasDelimiter {
			ignoredLinesCount++
			continue
		}

		if !isValidEnvKey(keyPart) {
			ignoredLinesCount++
			continue
		}

		// Valid key found!
		keys = append(keys, keyPart)

		// Scan the value part to update the multi-line quote state
		for i := 0; i < len(valPart); i++ {
			ch := valPart[i]
			if inD {
				if ch == '"' && (i == 0 || valPart[i-1] != '\\') {
					inD = false
				}
			} else if inS {
				if ch == '\'' && (i == 0 || valPart[i-1] != '\\') {
					inS = false
				}
			} else {
				if ch == '"' {
					inD = true
				} else if ch == '\'' {
					inS = true
				}
			}
		}
		inSingleQuote = inS
		inDoubleQuote = inD
	}

	return keys, ignoredLinesCount, scanner.Err()
}

func isValidEnvKey(k string) bool {
	if len(k) == 0 {
		return false
	}
	for i, ch := range k {
		if i == 0 {
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || ch == '_') {
				return false
			}
		} else {
			if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_') {
				return false
			}
		}
	}
	return true
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
