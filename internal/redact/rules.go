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

// defaultRuleNames lists the redaction rules applied at LevelDefault, in the
// order RedactString applies them. Consumers (e.g. capsule manifests) must
// derive rule listings from RuleNames so they cannot drift from the engine.
var defaultRuleNames = []string{
	"env_values",
	"cli_secret_flags",
	"secret_key_values",
	"url_credentials",
	"bearer_tokens",
	"jwt_tokens",
	"home_directory",
}

// RuleNames returns the names of the redaction rules active at the given
// level. It returns nil for LevelOff.
func RuleNames(level Level) []string {
	switch level {
	case LevelOff:
		return nil
	case LevelStrict:
		names := make([]string, 0, len(defaultRuleNames)+1)
		names = append(names, defaultRuleNames...)
		return append(names, "strict_long_tokens")
	default:
		return append([]string(nil), defaultRuleNames...)
	}
}

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
	// bearerTokenPattern matches Bearer credentials in Authorization headers
	// or header-like log fragments, case-insensitively.
	bearerTokenPattern = regexp.MustCompile(`(?i)\b(bearer\s+)[A-Za-z0-9._~+/=-]+`)
	// secretKeyValuePattern matches KEY=VALUE assignments whose key name
	// indicates secret material regardless of case (db_password=, api_key=,
	// auth_token=, ...). The uppercase-only envValuePattern misses these, and
	// lowercase diagnostics (exit_code=1) must stay untouched, so this pattern
	// is scoped to secret-bearing key names only.
	secretKeyValuePattern = regexp.MustCompile("(?im)(^|[\\s'\"`\\[])([A-Z0-9_]*(?:password|passwd|secret|token|api_?key|credential|auth_)[A-Z0-9_]*=)(\"[^\"]*\"|'[^']*'|[^\\s'\"`\\]]*)")
	// cliSecretPattern matches common CLI flag patterns that carry secrets.
	// Covers: --password=secret, --password secret, --token=abc, --api-key=xyz, etc.
	// Quoted values ("multi word" / 'multi word') are consumed entirely.
	// Case-insensitive via (?i:...).
	cliSecretPattern = regexp.MustCompile(`(?i)(--(?:password|token|api[-_]key|client[-_]secret|secret|auth[-_]token)(?:=|\s+))("[^"]*"|'[^']*'|[^\s]+)`)
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

// redactBearerTokens replaces Bearer credentials in Authorization headers.
func redactBearerTokens(input string) string {
	return bearerTokenPattern.ReplaceAllString(input, "${1}<redacted>")
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
