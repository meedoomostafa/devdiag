package redact

import (
	"strings"
	"testing"
)

// TestKeyBoundaryPunctuation pins the leading boundary. Only whitespace, quotes,
// backtick and "[" used to qualify, so a secret preceded by any other
// punctuation was never matched and was emitted verbatim.
func TestKeyBoundaryPunctuation(t *testing.T) {
	const canary = "BOUNDARYCANARY123"
	// ">" and "{" are deliberately absent. ">" is excluded so the engine's own
	// markers, which all end with ">", cannot create a boundary the input did not
	// have. "{" is excluded because it lets the rules reach inside "${...}", and a
	// skipped match still consumes its span; see wsDelim and #53. ":" and "/" are
	// excluded so the rules stay out of URLs, which redactURL owns. "=" is
	// excluded because an assignment introduced by another "=" is already inside
	// the preceding value.
	prefixes := []string{"(", "<", ",", ";", "|", "+", "&", "?", "#", "@", "!", "*", "%", "^", "~", ")", "}", "]", "[", `"`, "'", " ", "\t"}
	for _, lvl := range []Level{LevelDefault, LevelStrict} {
		e := NewEngine(lvl)
		for _, p := range prefixes {
			in := "x" + p + "API_KEY=" + canary
			if out := e.RedactString(in, "test"); strings.Contains(out, canary) {
				t.Errorf("level %s: prefix %q leaked: in=%q out=%q", lvl, p, in, out)
			}
		}
	}
}

// TestKeyBoundaryRealShapes covers the shapes that made this worth fixing.
func TestKeyBoundaryRealShapes(t *testing.T) {
	const canary = "REALSHAPECANARY123"
	for _, lvl := range []Level{LevelDefault, LevelStrict} {
		e := NewEngine(lvl)
		for _, in := range []string{
			"GET https://api.example.com/v1/users?api_key=" + canary + "&format=json",
			"https://x.io/a?format=json&api_key=" + canary,
			"fetch failed: https://x.io/a?access_token=" + canary,
			"at connect(API_KEY=" + canary + ")",
			// A bare-key YAML flow mapping is tracked in #53: "{" cannot be a
			// boundary until the final-pass rework lands.
		} {
			out := e.RedactString(in, "test")
			if strings.Contains(out, canary) {
				t.Errorf("level %s leaked: in=%q out=%q", lvl, in, out)
			}
			if again := e.RedactString(out, "test"); again != out {
				t.Errorf("not idempotent: once=%q twice=%q", out, again)
			}
		}
	}
}

// TestParameterExpansionStillOwnedByItsRule guards the reason the open brace was
// carved out of the boundary class. The colon rule must not reach inside
// ${...}: it would consume the operator and, for a nested expansion, stop at the
// inner brace and leave the suffix visible.
func TestParameterExpansionStillOwnedByItsRule(t *testing.T) {
	e := NewEngine(LevelDefault)
	for _, tc := range []struct{ in, want string }{
		{"services.app.environment references ${API_TOKEN:-CANARYCOMPOSEDEFAULT999}", "services.app.environment references ${API_TOKEN:-<redacted>}"},
		{"app.env references ${A_TOKEN:-${B}-real-secret}", "app.env references ${A_TOKEN:-<redacted>}"},
		{"db.env references ${DB_PASSWORD-supersecret}", "db.env references ${DB_PASSWORD-<redacted>}"},
		{"app.env references ${NODE_VERSION:-20}", "app.env references ${NODE_VERSION:-20}"},
		{"app.env references ${API_TOKEN}", "app.env references ${API_TOKEN}"},
	} {
		if got := e.RedactString(tc.in, "test"); got != tc.want {
			t.Errorf("RedactString(%q)\n  got  %q\n  want %q", tc.in, got, tc.want)
		}
	}
}

// TestDeclinedMatchDoesNotHideNestedSecret covers a secret assignment sitting
// inside the value extent of an earlier assignment whose key is not
// secret-named. The declined span used to be skipped whole, so the nested key
// was never examined.
func TestDeclinedMatchDoesNotHideNestedSecret(t *testing.T) {
	const canary = "NESTEDCANARY123"
	for _, lvl := range []Level{LevelDefault, LevelStrict} {
		e := NewEngine(lvl)
		for _, in := range []string{
			"a=1,deployKey=" + canary,
			"exit_code=0,API_TOKEN=" + canary,
			"path=/tmp/x;db_password=" + canary,
			"mode=fast|sessionid=" + canary,
		} {
			out := e.RedactString(in, "test")
			if strings.Contains(out, canary) {
				t.Errorf("level %s leaked: in=%q out=%q", lvl, in, out)
			}
			if again := e.RedactString(out, "test"); again != out {
				t.Errorf("not idempotent: once=%q twice=%q", out, again)
			}
		}
	}

	// Benign text either side of a declined match must survive.
	e := NewEngine(LevelDefault)
	got := e.RedactString("exit_code=0,duration_ms=1234", "test")
	if got != "exit_code=0,duration_ms=1234" {
		t.Errorf("benign assignments altered: %q", got)
	}
}

// TestURLUserinfoLeftToTheURLRule keeps the colon rule out of a URL authority.
// With punctuation as a boundary the rule can match userinfo whose username is
// secret-named, and because its value is not bounded at "@" it consumed the host
// and path:
//
//	https://x-access-token:tok@github.com/org/repo.git -> https://x-access-token:<redacted>
//
// That destroys the diagnostic rather than leaking, but a token URL is exactly
// what a git remote failure prints. Found by CodeRabbit.
func TestURLUserinfoLeftToTheURLRule(t *testing.T) {
	e := NewEngine(LevelDefault)
	for _, tc := range []struct{ in, want string }{
		{
			"https://x-access-token:ghp_TOKENCANARY@github.com/org/repo.git",
			"https://x-access-token:<redacted>@github.com/org/repo.git",
		},
		{
			"remote add origin https://user:PASSCANARY@gitlab.com/a/b.git",
			"remote add origin https://user:<redacted>@gitlab.com/a/b.git",
		},
		{
			"git+ssh://deploy_token:SECRETCANARY@host:22/path",
			"git+ssh://deploy_token:<redacted>@host:22/path",
		},
	} {
		got := e.RedactString(tc.in, "test")
		if got != tc.want {
			t.Errorf("RedactString(%q)\n  got  %q\n  want %q", tc.in, got, tc.want)
		}
		if again := e.RedactString(got, "test"); again != got {
			t.Errorf("not idempotent: once %q twice %q", got, again)
		}
	}

	// A secret in a query string is outside the authority and must still be
	// masked, which is why the span stops where it does.
	if got := e.RedactString("https://x.io/v1?api_key=QUERYSECRET123", "test"); strings.Contains(got, "QUERYSECRET123") {
		t.Errorf("query parameter leaked: %q", got)
	}
}
