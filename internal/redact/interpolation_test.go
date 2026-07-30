package redact

import (
	"strings"
	"testing"
)

// TestPOSIXExpansionOperators pins every POSIX parameter-expansion operator.
// The rule originally matched only "-" and ":-", and because "{" is not a key
// boundary for any assignment rule either, the remaining operators were masked
// by no rule at all and leaked at both redaction levels.
func TestPOSIXExpansionOperators(t *testing.T) {
	const secret = "PRODSECRETCANARY123"

	secretNamed := []string{
		"${API_TOKEN:-" + secret + "}",
		"${API_TOKEN-" + secret + "}",
		"${API_TOKEN:=" + secret + "}",
		"${API_TOKEN=" + secret + "}",
		"${API_TOKEN:+" + secret + "}",
		"${API_TOKEN+" + secret + "}",
		"${API_TOKEN:?" + secret + "}",
		"${API_TOKEN?" + secret + "}",
		"${DB_PASSWORD:=" + secret + "}",
		"${private_key:+" + secret + "}",
	}
	for _, lvl := range []Level{LevelDefault, LevelStrict} {
		e := NewEngine(lvl)
		for _, in := range secretNamed {
			t.Run(string(lvl)+" "+in, func(t *testing.T) {
				out := e.RedactString(in, "test")
				if strings.Contains(out, secret) {
					t.Errorf("leaked: in=%q out=%q", in, out)
				}
				if !strings.Contains(out, "<redacted>") {
					t.Errorf("expected marker: in=%q out=%q", in, out)
				}
				if again := e.RedactString(out, "test"); again != out {
					t.Errorf("not idempotent: once=%q twice=%q", out, again)
				}
			})
		}
	}
}

// TestPOSIXExpansionBenignNamesSurvive keeps the widened operator set from
// masking diagnostics whose variable name is not secret-bearing.
func TestPOSIXExpansionBenignNamesSurvive(t *testing.T) {
	e := NewEngine(LevelDefault)
	for _, in := range []string{
		"${NODE_VERSION:=20}",
		"${NODE_VERSION:+true}",
		"${OAUTH_ENABLED:?must be set}",
		"${AUTHOR=someone}",
		"${BUILD_MODE+release}",
	} {
		if out := e.RedactString(in, "test"); out != in {
			t.Errorf("benign interpolation altered: in=%q out=%q", in, out)
		}
	}
}

// TestPOSIXExpansionExistingBehaviourPreserved guards the cases the original
// rule already handled, including the nested form whose whole point is that the
// suffix after an inner ${...} must not survive.
func TestPOSIXExpansionExistingBehaviourPreserved(t *testing.T) {
	e := NewEngine(LevelDefault)
	tests := []struct{ in, want string }{
		{"app.env references ${A_TOKEN:-${B}-real-secret}", "app.env references ${A_TOKEN:-<redacted>}"},
		{"db.env references ${DB_PASSWORD-supersecret}", "db.env references ${DB_PASSWORD-<redacted>}"},
		{"app.env references ${API_TOKEN:-}", "app.env references ${API_TOKEN:-}"},
		{"app.env references ${API_TOKEN}", "app.env references ${API_TOKEN}"},
		{"app.env references ${API_TOKEN:-broken", "app.env references ${API_TOKEN:-broken"},
	}
	for _, tt := range tests {
		if got := e.RedactString(tt.in, "test"); got != tt.want {
			t.Errorf("RedactString(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestNonOperandExpansionsUntouched keeps the widened operator set from
// swallowing expansion syntax that carries no literal operand. Substring
// expansion is the important one: "${VAR:3:4}" has a digit after the colon,
// which [-=+?] must not match.
func TestNonOperandExpansionsUntouched(t *testing.T) {
	e := NewEngine(LevelDefault)
	for _, in := range []string{
		"${API_TOKEN:3:4}",
		"${API_TOKEN#prefix}",
		"${API_TOKEN%suffix}",
		"${API_TOKEN//a/b}",
		"${#API_TOKEN}",
	} {
		if out := e.RedactString(in, "test"); out != in {
			t.Errorf("expansion altered: in=%q out=%q", in, out)
		}
	}
}
