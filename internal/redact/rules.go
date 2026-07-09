package redact

import (
	"os"
	"regexp"
	"strings"
)

// Level controls redaction aggressiveness.
type Level string

const (
	LevelDefault Level = "default"
	LevelStrict  Level = "strict"
	LevelOff     Level = "off"
)

var (
	// userInfoPattern matches URLs with embedded credentials.
	userInfoPattern = regexp.MustCompile(`(\w+://)([^@]+)@`)
	// jwtPattern matches JWTs (eyJ prefix) in default mode.
	jwtPattern = regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b`)
	// strictTokenPattern matches long hex/base64 strings; used only in strict mode.
	strictTokenPattern = regexp.MustCompile(`\b([a-fA-F0-9]{40,}|[A-Za-z0-9+/]{40,}=*)\b`)
	// quotedKeyMaterialPattern matches long base64-like material echoed by tools
	// in quoted diagnostics, such as malformed multiline .env key material.
	quotedKeyMaterialPattern = regexp.MustCompile(`"([A-Za-z0-9+/]{32,}=*)"`)
	// envValuePattern matches KEY=VALUE assignments in logs, shell args, JSON-
	// quoted command arrays, and Go slice-formatted args while preserving
	// surrounding delimiters. Values that are themselves quoted (KEY="a b" or
	// KEY='a b') are consumed entirely, including embedded whitespace.
	envValuePattern = regexp.MustCompile("(?m)(^|[\\s'\"`\\[])([A-Z_][A-Z0-9_]*=)(\"[^\"]*\"|'[^']*'|[^\\s'\"`\\]]*)")
	// secretKeyValuePattern matches KEY=VALUE assignments whose key name
	// indicates secret material regardless of case (db_password=, api_key=,
	// auth_token=, ...). The uppercase-only envValuePattern misses these, and
	// lowercase diagnostics (exit_code=1) must stay untouched, so this pattern
	// is scoped to secret-bearing key names only.
	secretKeyValuePattern = regexp.MustCompile("(?im)(^|[\\s'\"`\\[])([A-Z0-9_]*(?:password|passwd|secret|token|api_?key|credential|auth)[A-Z0-9_]*=)(\"[^\"]*\"|'[^']*'|[^\\s'\"`\\]]*)")
	// cliSecretPattern matches common CLI flag patterns that carry secrets.
	// Covers: --password=secret, --password secret, --token=abc, --api-key=xyz, etc.
	// Case-insensitive via (?i:...).
	cliSecretPattern = regexp.MustCompile(`(?i)(--(?:password|token|api[-_]key|client[-_]secret|secret|auth[-_]token)(?:=|\s+))([^\s]+)`)
)

// homeDir caches the user's home directory.
var homeDir = os.Getenv("HOME")

// redactURL replaces credentials in URLs.
func redactURL(input string) string {
	return userInfoPattern.ReplaceAllStringFunc(input, func(match string) string {
		parts := userInfoPattern.FindStringSubmatch(match)
		if len(parts) >= 3 {
			userInfo := parts[2]
			if idx := strings.Index(userInfo, ":"); idx != -1 {
				user := userInfo[:idx]
				return parts[1] + user + ":<redacted>@"
			}
		}
		return parts[1] + "<redacted>@"
	})
}

// redactJWT replaces JWTs in default mode.
func redactJWT(input string) string {
	return jwtPattern.ReplaceAllString(input, "<jwt>")
}

// redactStrictTokens replaces long hex/base64 strings in strict mode.
func redactStrictTokens(input string) string {
	return strictTokenPattern.ReplaceAllString(input, "<token>")
}

// redactQuotedKeyMaterial replaces long quoted base64-like tokens that often
// come from PEM/JWK/key material echoed in tool error messages.
func redactQuotedKeyMaterial(input string) string {
	return quotedKeyMaterialPattern.ReplaceAllString(input, `"<token>"`)
}

// redactHome replaces home directory paths.
func redactHome(input string) string {
	if homeDir == "" {
		return input
	}
	return strings.ReplaceAll(input, homeDir, "~")
}

// redactEnvValues replaces values in KEY=VALUE patterns.
func redactEnvValues(input string) string {
	result := envValuePattern.ReplaceAllString(input, "${1}${2}<redacted>")
	return secretKeyValuePattern.ReplaceAllString(result, "${1}${2}<redacted>")
}

// redactCLISecrets replaces values after common secret-bearing CLI flags.
func redactCLISecrets(input string) string {
	return cliSecretPattern.ReplaceAllString(input, "${1}<redacted>")
}
