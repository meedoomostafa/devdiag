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

// TestAuthorizationHeaderUnknownScheme covers a credential that is not preceded
// by a recognised scheme. The optional scheme group used to match any
// alphanumeric word, so it could swallow the credential itself and leave the
// text after it masked instead:
//
//	Authorization: shortcred123 extra  ->  credential visible, "extra" masked
//
// and with a long credential the result was not even a fixed point. Anything
// after the header that is not a known scheme is now masked wholesale.
func TestAuthorizationHeaderUnknownScheme(t *testing.T) {
	for _, lvl := range []Level{LevelDefault, LevelStrict} {
		e := NewEngine(lvl)
		for _, tc := range []struct{ in, canary string }{
			{"Authorization: shortcredCANARY111 extra", "shortcredCANARY111"},
			{"AuthoriZAtion:A000000000000000000000000000000000000000 0", "A000000000000000000000000000000000000000"},
			{"Authorization: CANARYNOSCHEME2222", "CANARYNOSCHEME2222"},
			{"Authorization: AWS4-HMAC-SHA256 Credential=x/y, Signature=CANARYSIG3333", "CANARYSIG3333"},
		} {
			out := e.RedactString(tc.in, "test")
			if strings.Contains(out, tc.canary) {
				t.Errorf("level %s leaked %q\n  in  %q\n  out %q", lvl, tc.canary, tc.in, out)
			}
			if again := e.RedactString(out, "test"); again != out {
				t.Errorf("level %s not idempotent for %q\n  once  %q\n  twice %q", lvl, tc.in, out, again)
			}
		}
	}

	// Known schemes stay visible so the diagnostic keeps its meaning.
	e := NewEngine(LevelDefault)
	for _, tc := range []struct{ in, want string }{
		{`curl -H "Authorization: Bearer abcdef123456" failed`, `curl -H "Authorization: Bearer <redacted>" failed`},
		{`curl -H "Authorization: Basic dXNlcjpwYXNz" x`, `curl -H "Authorization: Basic <redacted>" x`},
		{"Authorization: Digest cnonce=abc", "Authorization: Digest <redacted>"},
	} {
		if got := e.RedactString(tc.in, "test"); got != tc.want {
			t.Errorf("RedactString(%q)\n  got  %q\n  want %q", tc.in, got, tc.want)
		}
	}
}

// TestAuthorizationHeaderStaysOnItsLine pins the header boundary. Go's \s
// includes newline and carriage return, so horizontal whitespace around the
// colon and after the scheme is required: with \s a header carrying a trailing
// space and no value consumed the line break and redacted the next header.
// Found by CodeRabbit.
func TestAuthorizationHeaderStaysOnItsLine(t *testing.T) {
	e := NewEngine(LevelDefault)
	for _, tc := range []struct{ in, want string }{
		{"Authorization: Basic \r\nX-Trace: keepme", "Authorization: Basic <redacted>\r\nX-Trace: keepme"},
		{"Authorization: Basic \nX-Trace: keepme", "Authorization: Basic <redacted>\nX-Trace: keepme"},
		{"Authorization:\r\nX-Trace: keepme", "Authorization:<redacted>\r\nX-Trace: keepme"},
		{"Authorization: Bearer abc\r\nX-Trace: keepme", "Authorization: Bearer <redacted>\r\nX-Trace: keepme"},
	} {
		got := e.RedactString(tc.in, "test")
		if got != tc.want {
			t.Errorf("RedactString(%q)\n  got  %q\n  want %q", tc.in, got, tc.want)
		}
		if again := e.RedactString(got, "test"); again != got {
			t.Errorf("not idempotent: once %q twice %q", got, again)
		}
	}
}
