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
	// envValuePattern matches KEY=VALUE style assignments and redacts the value.
	envValuePattern = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*=)(.*)$`)
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

// redactHome replaces home directory paths.
func redactHome(input string) string {
	if homeDir == "" {
		return input
	}
	return strings.ReplaceAll(input, homeDir, "~")
}

// redactEnvValues replaces values in KEY=VALUE patterns.
func redactEnvValues(input string) string {
	return envValuePattern.ReplaceAllString(input, "${1}<redacted>")
}
