package redact

import (
	"regexp"
	"strings"
	"testing"
)

// identifierKey matches names that could plausibly be an assignment target.
// Without it the property fires on comparison expressions like "AuthA!=x",
// where redacting the right-hand side would be wrong.
var identifierKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

// FuzzRedactString drives the redaction engine with arbitrary input. This is
// the security-critical parser: everything DevDiag prints, saves, or ships
// in a capsule passes through it. It must never panic, and - the property
// that actually matters - it must never leak a secret that its own rules
// claim to redact.
func FuzzRedactString(f *testing.F) {
	f.Add("DATABASE_URL=postgres://user:hunter2@localhost:5432/app")
	f.Add("Authorization: Bearer abcdef123456")
	f.Add("api_key=sk-livetoken0000")
	f.Add("${API_TOKEN:-fallbacksecret}")
	f.Add("nothing sensitive here")
	f.Add("")
	f.Add("KEY=\x00\x01\x02")

	f.Fuzz(func(t *testing.T, in string) {
		// Both non-off levels must hold the same invariants; strict only
		// ever redacts more.
		for _, level := range []Level{LevelDefault, LevelStrict} {
			e := NewEngine(level)
			out := e.RedactString(in, "fuzz")
			// Contract: redaction never grows input unboundedly (a
			// pathological rewrite loop would show up here).
			if len(out) > len(in)*8+64 {
				t.Fatalf("level %s: output grew from %d to %d bytes", level, len(in), len(out))
			}
			// Contract: an env assignment whose key names a secret must not
			// survive with its value intact.
			if k, v, ok := strings.Cut(in, "="); ok {
				key := strings.TrimSpace(k)
				val := strings.TrimSpace(v)
				// Values shorter than 6 chars are skipped: single characters
				// coincidentally appear inside the key or the "<redacted>"
				// marker, which is a property artifact rather than a leak.
				if len(val) >= 6 && !strings.ContainsAny(val, " \t\n\r\"'") &&
					identifierKey.MatchString(key) &&
					IsSecretKeyName(key) &&
					strings.Contains(out, val) {
					t.Fatalf("level %s: secret-named assignment leaked its value\nkey=%q value=%q\nin=%q\nout=%q", level, key, val, in, out)
				}
			}
		}
	})
}

// FuzzRedactEvidence drives the source-aware evidence path, which decides
// whether a bare value is a secret based on its collector source name.
func FuzzRedactEvidence(f *testing.F) {
	f.Add("ci_env__job__build__AWS_SECRET_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE")
	f.Add("ci_env__job__build__NODE_VERSION", "20")
	f.Add("", "")
	f.Add("ci_env__\x00__X", "value")

	e := NewEngine(LevelDefault)
	f.Fuzz(func(t *testing.T, source, value string) {
		out := e.RedactEvidence(source, value)
		// Contract: when the engine classifies the source as secret-bearing,
		// the raw value must never survive. Short values are skipped because
		// the redaction marker itself contains common letters ("<redacted>"
		// trivially "contains" the value "a"), which is a property artifact,
		// not a leak.
		if len(value) >= 6 && isSecretSource(source) && strings.Contains(out, value) {
			t.Fatalf("secret-source value survived\nsource=%q value=%q out=%q", source, value, out)
		}
	})
}
