package redact

import (
	"strings"
	"testing"
)

// TestCookieValuesMasked covers cookie values whose names the classifier cannot
// know. A cookie carrying authentication or session state can be named anything,
// so per-key-name classification is inherently incomplete here.
func TestCookieValuesMasked(t *testing.T) {
	const canary = "COOKIECANARY123456"
	for _, lvl := range []Level{LevelDefault, LevelStrict} {
		e := NewEngine(lvl)
		for _, in := range []string{
			"Cookie: sessionid=" + canary,
			"Cookie: _app_state=" + canary + "; ab=1",
			"Cookie: csrftoken=x; __Host-auth=" + canary,
			"Set-Cookie: __Host-auth=" + canary + "; Secure; HttpOnly",
			"set-cookie: sid=" + canary + "; Path=/; SameSite=Lax",
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

// TestCookieStructurePreserved keeps everything a user actually debugs. Cookie
// names and attributes are what a broken session looks like; the value is not.
func TestCookieStructurePreserved(t *testing.T) {
	e := NewEngine(LevelDefault)
	for _, tc := range []struct{ in, want string }{
		{
			"Cookie: a=1; b=2",
			"Cookie: a=<redacted>; b=<redacted>",
		},
		{
			"Set-Cookie: sid=abc; Path=/; Domain=example.com; Secure; HttpOnly; SameSite=Strict",
			"Set-Cookie: sid=<redacted>; Path=/; Domain=example.com; Secure; HttpOnly; SameSite=Strict",
		},
		{
			// Expires carries commas and spaces; splitting on ";" must keep it.
			"Set-Cookie: sid=abc; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Max-Age=3600",
			"Set-Cookie: sid=<redacted>; Expires=Wed, 21 Oct 2015 07:28:00 GMT; Max-Age=3600",
		},
		{
			// The header must not reach past its own line.
			"Cookie: sid=abc\r\nX-Trace: keepme",
			"Cookie: sid=<redacted>\r\nX-Trace: keepme",
		},
		{
			// A bare attribute with no value stays as-is.
			"Set-Cookie: sid=abc; Partitioned; Priority=High",
			"Set-Cookie: sid=<redacted>; Partitioned; Priority=High",
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
}

// TestCookieAttributeNamesAreNotExempt covers a cookie whose name collides with
// a Set-Cookie attribute. A request Cookie header carries only cookie pairs -
// there are no attributes in it - and the first pair of a Set-Cookie is always
// the cookie itself, so exempting those by name is a bypass. Found by
// sol-secops.
func TestCookieAttributeNamesAreNotExempt(t *testing.T) {
	const canary = "ATTRNAMECANARY123"
	e := NewEngine(LevelDefault)
	for _, in := range []string{
		"Cookie: Path=" + canary,
		"Cookie: Secure=" + canary,
		"Cookie: Expires=" + canary,
		"Cookie: SameSite=" + canary + "; other=1",
		"Set-Cookie: Path=" + canary + "; Path=/; Secure",
		"Set-Cookie: Domain=" + canary + "; Domain=example.com",
	} {
		out := e.RedactString(in, "test")
		if strings.Contains(out, canary) {
			t.Errorf("attribute-named cookie leaked: in=%q out=%q", in, out)
		}
		if again := e.RedactString(out, "test"); again != out {
			t.Errorf("not idempotent: once=%q twice=%q", out, again)
		}
	}

	// The real attributes that follow the first Set-Cookie pair still survive.
	got := e.RedactString("Set-Cookie: Path=secretvalue; Path=/admin; Secure", "test")
	if !strings.Contains(got, "Path=/admin") {
		t.Errorf("genuine attribute lost: %q", got)
	}
}
