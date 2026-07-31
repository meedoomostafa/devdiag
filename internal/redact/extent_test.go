package redact

import "testing"

// TestValueExtentGiveBack pins the unquoted value extent. The extent used to
// stop at any delimiter, so the tail of a secret containing one stayed visible.
// Delimiters are now consumed and a maximal trailing run of closing delimiters
// is given back, which keeps surrounding structure intact.
func TestValueExtentGiveBack(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		// Structure that must survive byte-identically.
		{"single quoted shell arg", "printf 'API_KEY=secret123'", "printf 'API_KEY=<redacted>'"},
		{"double quoted shell arg", `printf "API_KEY=secret123"`, `printf "API_KEY=<redacted>"`},
		{"json nested", `{"args":["API_KEY=secret123"]}`, `{"args":["API_KEY=<redacted>"]}`},
		{"go slice", `args=[API_KEY=secret123]`, `args=[API_KEY=<redacted>]`},
		{"go slice multi element", `args=[API_KEY=s1secret DB_PASSWORD=s2secret]`, `args=[API_KEY=<redacted> DB_PASSWORD=<redacted>]`},
		{"quoted value with space", `KEY="quoted value"`, `KEY=<redacted>`},

		// The leaks this closes.
		{"bracket mid value", "API_TOKEN=abc]def", "API_TOKEN=<redacted>"},
		{"backtick mid value", "API_TOKEN=abc`def", "API_TOKEN=<redacted>"},
		{"quote mid value", `API_TOKEN=abc"def`, `API_TOKEN=<redacted>`},
		{"double equals then bracket", "keY==]0000secret", "keY=<redacted>"},
		{"colon bracket mid value", "token: ab]cdef", "token: <redacted>"},

		// A value made only of closing delimiters must still be masked, not
		// handed back as structure.
		{"closers only", "API_TOKEN=]]]]", "API_TOKEN=<redacted>"},

		// Whitespace is the only hard bound, so a sibling query parameter is
		// masked along with the secret. That over-redacts rather than leaks, and
		// is the deliberate cost of not handing back text that later rules
		// rewrite - see splitValueTail.
		{"query tail masked", " api_key=SECRETVALUE&format=json", " api_key=<redacted>"},
		{"ampersand inside secret", "PASSWORD=a&bsecret", "PASSWORD=<redacted>"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := NewEngine(LevelDefault)
			got := e.RedactString(tc.in, "test")
			if got != tc.want {
				t.Errorf("RedactString(%q)\n  got  %q\n  want %q", tc.in, got, tc.want)
			}
			if again := e.RedactString(got, "test"); again != got {
				t.Errorf("not idempotent for %q\n  once  %q\n  twice %q", tc.in, got, again)
			}
		})
	}
}

// TestValueExtentFlowBoundaries keeps the colon rule bounded by the delimiters
// that separate entries, so sibling fields and document structure survive.
func TestValueExtentFlowBoundaries(t *testing.T) {
	e := NewEngine(LevelDefault)
	tests := []struct{ in, want string }{
		{`{"token": "abcsecret", "image": "nginx"}`, `{"token": <redacted>, "image": "nginx"}`},
		{"token: abcsecret\nimage: nginx", "token: <redacted>\nimage: nginx"},
	}
	for _, tt := range tests {
		got := e.RedactString(tt.in, "test")
		if got != tt.want {
			t.Errorf("RedactString(%q)\n  got  %q\n  want %q", tt.in, got, tt.want)
		}
	}
}

// TestValueExtentEmptyAndCloserOnlyValues separates a closer-only value that is
// really the enclosing structure from one that is really the value. Found by
// sol-secops: consuming the bracket of an empty assignment produced malformed
// output where the input had previously been left alone.
func TestValueExtentEmptyAndCloserOnlyValues(t *testing.T) {
	e := NewEngine(LevelDefault)
	tests := []struct{ name, in, want string }{
		// The "]" closes the "[" in the prefix, so it is structure and the
		// empty value must be left alone.
		{"empty value inside brackets", `args=[API_KEY=]`, `args=[API_KEY=]`},
		{"empty value inside quotes", `printf "API_KEY="`, `printf "API_KEY="`},
		{"empty value at line start", `API_KEY=`, `API_KEY=`},
		// No opening delimiter precedes it, so the closers are the value.
		{"closers only value", `API_TOKEN=]]]]`, `API_TOKEN=<redacted>`},
		{"closers only after space", ` API_TOKEN=]]]]`, ` API_TOKEN=<redacted>`},
		// An escaped quote must not end the quoted value, or the output is left
		// with a dangling quote and an escaped quote inside a JSON string
		// produces invalid JSON.
		{"escaped quote in quoted value", `KEY="a\"bsecret"`, `KEY=<redacted>`},
		{"escaped quote json", `{"token": "a\"bsecret"}`, `{"token": <redacted>}`},
		{"single quotes carry no escape", `KEY='a\'`, `KEY=<redacted>`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := e.RedactString(tc.in, "test")
			if got != tc.want {
				t.Errorf("RedactString(%q)\n  got  %q\n  want %q", tc.in, got, tc.want)
			}
			if again := e.RedactString(got, "test"); again != got {
				t.Errorf("not idempotent: once %q twice %q", got, again)
			}
		})
	}
}
