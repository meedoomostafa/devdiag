package fix

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var (
	validEnvKeyRe      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	validServiceNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)
)

// Validators bind and sanitize evidence values before they are used in commands.

// ValidatePath checks that a path is safe: not empty, not absolute unless within
// a restricted set of system paths, and free of traversal.
func ValidatePath(root, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("path is empty")
	}

	cleanValue := filepath.Clean(value)

	// If absolute, allow only a few safe system paths
	if filepath.IsAbs(cleanValue) {
		allowedPrefixes := []string{"/tmp", "/var/tmp", "/dev/shm", "/home", "/usr/local"}
		for _, prefix := range allowedPrefixes {
			rel, err := filepath.Rel(prefix, cleanValue)
			if err != nil {
				continue
			}
			if rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)) {
				return cleanValue, nil
			}
		}
		return "", fmt.Errorf("absolute path not in allowed prefix: %s", value)
	}

	// Relative path: resolve against root if provided
	if root != "" {
		cleanRoot := filepath.Clean(root)
		if !filepath.IsAbs(cleanRoot) {
			return "", fmt.Errorf("root must be absolute: %s", root)
		}

		resolved := filepath.Join(cleanRoot, cleanValue)
		rel, err := filepath.Rel(cleanRoot, resolved)
		if err != nil {
			return "", fmt.Errorf("could not resolve relative path: %w", err)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return "", fmt.Errorf("path contains traversal outside root: %s", value)
		}
		return resolved, nil
	}

	// If no root, still reject any traversal components in the relative path
	for _, part := range strings.Split(cleanValue, string(filepath.Separator)) {
		if part == ".." {
			return "", fmt.Errorf("path contains traversal: %s", value)
		}
	}

	return cleanValue, nil
}

// ValidatePort checks that a string is a valid TCP/UDP port number.
func ValidatePort(value string) (int, error) {
	if value == "" {
		return 0, fmt.Errorf("port is empty")
	}
	p, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("port is not a number: %s", value)
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("port out of range: %d", p)
	}
	return p, nil
}

// ValidateServiceName checks that a value is a valid service identifier.
func ValidateServiceName(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("service name is empty")
	}
	if !validServiceNameRe.MatchString(value) {
		return "", fmt.Errorf("invalid service name: %s", value)
	}
	return value, nil
}

// ValidateEnvKey checks that a value is a valid environment variable name.
func ValidateEnvKey(value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("env key is empty")
	}
	if !validEnvKeyRe.MatchString(value) {
		return "", fmt.Errorf("invalid env key: %s", value)
	}
	return value, nil
}
