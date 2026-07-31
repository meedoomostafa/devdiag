package redact

import (
	"strings"
	"testing"
)

// TestSessionAndSignatureKeyNames covers credential-bearing key names the
// classifier did not recognise. A session identifier is a bearer credential -
// possession is enough to impersonate - and a presigned-URL signature is the
// component that grants the request its authority.
func TestSessionAndSignatureKeyNames(t *testing.T) {
	secret := []string{
		"sessionid", "session_id", "sessionId", "JSESSIONID", "PHPSESSID",
		"sid", "SID", "cookie_sid",
		"signature", "Signature", "X-Amz-Signature", "request_signature",
		"sig", "SIG", "url_sig",
	}
	for _, key := range secret {
		if !IsSecretKeyName(key) {
			t.Errorf("IsSecretKeyName(%q) = false, want true", key)
		}
	}

	// Segment anchoring must keep ordinary words out.
	notSecret := []string{
		"sigma", "signal", "signed_url_base", "design",
		"insidious", "consider", "resident", "sidebar", "aside",
		"session_count", "sessions",
	}
	for _, key := range notSecret {
		if IsSecretKeyName(key) {
			t.Errorf("IsSecretKeyName(%q) = true, want false", key)
		}
	}
}

// TestSessionAndSignatureValuesMasked drives the same names through the engine,
// including the lowercase query-parameter forms that the uppercase env rule
// cannot reach.
func TestSessionAndSignatureValuesMasked(t *testing.T) {
	const canary = "CANARYCREDENTIAL123"
	for _, lvl := range []Level{LevelDefault, LevelStrict} {
		e := NewEngine(lvl)
		for _, in := range []string{
			"Cookie: sessionid=" + canary,
			" sid=" + canary,
			" X-Amz-Signature=" + canary,
			" sig=" + canary,
			"signature: " + canary,
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

// TestAuthorizationHeaderSchemes covers credentials carried by an Authorization
// header under any scheme. Only "Bearer" was recognised, so HTTP Basic - the
// most common shape in a curl log - was emitted verbatim at both levels.
func TestAuthorizationHeaderSchemes(t *testing.T) {
	const canary = "dXNlcjpDQU5BUlkxMjM="
	for _, lvl := range []Level{LevelDefault, LevelStrict} {
		e := NewEngine(lvl)
		for _, in := range []string{
			`curl -H "Authorization: Basic ` + canary + `" https://x.io`,
			`curl -H "Proxy-Authorization: Basic ` + canary + `"`,
			"Authorization: Digest " + canary,
			"authorization: token " + canary,
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

	// The scheme stays visible so the diagnostic keeps its meaning, and the
	// existing Bearer expectation must not change.
	e := NewEngine(LevelDefault)
	got := e.RedactString(`curl -H "Authorization: Bearer abcdef123456" failed`, "test")
	want := `curl -H "Authorization: Bearer <redacted>" failed`
	if got != want {
		t.Errorf("bearer expectation changed\n  got  %q\n  want %q", got, want)
	}
	if got := e.RedactString(`curl -H "Authorization: Basic `+canary+`" x`, "test"); !strings.Contains(got, "Basic <redacted>") {
		t.Errorf("scheme not preserved: %q", got)
	}
}
