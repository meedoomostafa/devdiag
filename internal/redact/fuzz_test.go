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

// valueDelimiters lists the characters that bound an unquoted value extent in
// the assignment rules, and therefore the characters whose presence inside a
// value puts it outside the leak property below. It must stay in step with the
// notWsDelim class in rules.go.
// valueDelimiters lists the characters that bound an unquoted value extent in
// the assignment rules, and therefore the characters whose presence inside a
// value puts it outside the leak property below. Whitespace is now the only
// hard bound: quotes, backticks, and brackets are consumed by the extent and
// handed back afterwards by splitValueTail, so values containing them are in
// scope for the property.
const valueDelimiters = valueHardBounds

// colonValueDelimiters lists the characters that bound a COLON-assigned value.
// The colon extent allows spaces and backticks but is bounded by the YAML and
// JSON flow delimiters, so it needs its own skip set. Leading runs of "]" are
// covered by explicit tests rather than this property, for the same reason as
// the "=" family.
const colonValueDelimiters = "\n\r,"

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
	// YAML block scalars: the indicator was masked while the indented body
	// leaked verbatim. Seeds cover the indicator variants, the compact
	// sequence entry whose body sits at the key column, tab indentation
	// (invalid YAML, so the scanner must fail toward redaction), and a
	// benign key name carrying PEM private key material.
	f.Add("private_key: |\n  -----BEGIN RSA PRIVATE KEY-----\n  MIIEowIBAAKCAQEA\n")
	f.Add("api_token: |-2 # note\n  tokenmaterial0000\n")
	f.Add("items:\n- private_key: |\n  bodyatkeycolumn000\n- name: next\n")
	f.Add("private_key: |\n\ttabindentedsecret0\n")
	f.Add("data: |\n  -----BEGIN OPENSSH PRIVATE KEY-----\n  keymaterial00000\n")
	f.Add("tls.key: LS0tLS1CRUdJTiBQUklWQVRF\n")
	// Runs of leading delimiters in a value extent, which the leak property
	// below cannot reach because it skips delimiter-bearing values.
	f.Add("API_TOKEN=]]hunter2secret")
	f.Add("API_TOKEN=``hunter2secret")
	f.Add("db_password: ]]hunter2secret")
	f.Add("db_password: hunter2secret")
	f.Add("db_password\v: hunter2secret")
	// POSIX parameter-expansion operators beyond ":-" and "-", which were
	// owned by no rule: the interpolation rule skipped the operator and the
	// assignment rules cannot reach inside "${...}".
	f.Add("${API_TOKEN:=prodsecret000}")
	f.Add("${API_TOKEN:+prodsecret000}")
	f.Add("${API_TOKEN?prodsecret000}")
	f.Add("${API_TOKEN:3:4}")
	f.Add("${API_TOKEN[0]:-arraysecret000}")
	f.Add("${API_TOKEN:-a\\}bracesecret000}")
	// Delimiters inside a value, which the property could not reach before the
	// extent was widened, plus the query-separator and closers-only shapes.
	f.Add("API_TOKEN=abc]defsecret")
	f.Add("API_TOKEN=abc`defsecret")
	f.Add("token: ab]cdefsecret")
	f.Add("API_TOKEN=]]]]")
	f.Add(" api_key=SECRETVALUE&format=json")
	f.Add("PASSWORD=a&bsecret")
	// Closer-only values: the first is a value, the second closes the bracket
	// opened in the prefix and marks an empty assignment.
	f.Add("API_TOKEN=]]]]")
	f.Add("args=[API_KEY=]")
	f.Add("KEY=\"a\\\"bsecret\"")
	f.Add("{\"token\": \"a\\\"bsecret\"}")
	f.Add("KEY='a\\'")
	// Session identifiers, request signatures, and Authorization schemes other
	// than Bearer, none of which were recognised as credentials.
	f.Add("Cookie: sessionid=canarysession00")
	f.Add(" sig=canarysignature00")
	f.Add("Authorization: Basic dXNlcjpwYXNzd29yZA==")
	f.Add("Authorization: Basic <redacted>")
	f.Add("'private_key': |\n  singlequotedkeybody0\n")
	f.Add("---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nssh2body000\n")
	f.Add("\tprivate_key: |\n        tabheaderbody000\n")

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
			// Contract: redaction is idempotent. A rule that keeps
			// rewriting its own output would corrupt evidence and could
			// loop; this pins the fixed point.
			if again := e.RedactString(out, "fuzz"); again != out {
				t.Fatalf("level %s: not idempotent\nin=%q\nonce=%q\ntwice=%q", level, in, out, again)
			}
			// Contract: an env assignment whose key names a secret must not
			// survive with its value intact.
			if k, v, ok := strings.Cut(in, "="); ok {
				key := strings.TrimSpace(k)
				val := strings.TrimSpace(v)
				// Values shorter than 6 chars are skipped: single characters
				// coincidentally appear inside the key or the "<redacted>"
				// marker, which is a property artifact rather than a leak.
				//
				// Key names and the redaction marker are stripped before the
				// search for the same reason. Redaction masks values and never
				// rewrites key names, so a value that only survives *inside*
				// its own key ("ApikeY000000=000000") is an artifact of the
				// substring search rather than a leak. Stripping keeps the
				// property honest about value survival anywhere else,
				// including after a separator ("KEY= secret").
				haystack := strings.ReplaceAll(out, key, "")
				haystack = strings.ReplaceAll(haystack, "<redacted>", "")
				// Values containing a delimiter character are out of scope for
				// this property. The unquoted value extent is deliberately
				// bounded at whitespace, quotes, backtick, and "]" so that
				// surrounding structure survives - notably the closing bracket
				// of Go slice-formatted arguments
				// ("args=[API_KEY=<redacted>]"). The consequence is that the
				// tail of a secret which itself contains such a character can
				// remain visible. Fixing that needs the leading delimiter as
				// matching context rather than a wider extent, which means
				// reworking value semantics shared by the whole assignment
				// family; tracked separately rather than rushed in alongside
				// the multi-line secret work.
				//
				// A LEADING delimiter is covered, and is asserted directly by
				// TestBracketLeadingSecretValue.
				// A value that itself begins with the separator is out of scope:
				// this property splits on the first separator while the regex
				// treats it as part of the separator group, so the preserved
				// separator reads as if it were the head of a surviving value.
				// Such shapes are covered by explicit cases in extent_test.go.
				if len(val) >= 6 && !strings.ContainsAny(val, valueDelimiters) &&
					!strings.HasPrefix(val, "=") &&
					strings.TrimRight(val, valueClosers) != "" &&
					identifierKey.MatchString(key) &&
					IsSecretKeyName(key) {
					if strings.Contains(haystack, val) {
						t.Fatalf("level %s: secret-named assignment leaked its value\nkey=%q value=%q\nin=%q\nout=%q", level, key, val, in, out)
					}
					// A partial leak surfaces as the suffix beginning at a
					// delimiter, because that is where the value extent used to
					// stop. Checking only the whole value missed it: masking
					// "abc" in "abc]defsecret" still left "]defsecret" visible.
					if suffix := leakedDelimiterSuffix(val, haystack); suffix != "" {
						t.Fatalf("level %s: secret-named assignment leaked a value suffix\nkey=%q value=%q suffix=%q\nin=%q\nout=%q", level, key, val, suffix, in, out)
					}
				}
			}
			// Contract: the same holds for a colon assignment. This path is
			// materially different code - a separate pattern with a separate
			// value extent - and had no fuzz coverage at all, which is how a
			// doubled leading bracket survived in it after the "=" family was
			// fixed.
			if k, v, ok := strings.Cut(in, ":"); ok {
				key := strings.TrimSpace(k)
				val := strings.TrimSpace(v)
				haystack := strings.ReplaceAll(out, key, "")
				haystack = strings.ReplaceAll(haystack, "<redacted>", "")
				if len(val) >= 6 && !strings.ContainsAny(val, colonValueDelimiters) &&
					!strings.HasPrefix(val, ":") &&
					strings.TrimRight(val, valueClosers) != "" &&
					identifierKey.MatchString(key) &&
					IsSecretKeyName(key) {
					if strings.Contains(haystack, val) {
						t.Fatalf("level %s: secret-named colon assignment leaked its value\nkey=%q value=%q\nin=%q\nout=%q", level, key, val, in, out)
					}
					if suffix := leakedDelimiterSuffix(val, haystack); suffix != "" {
						t.Fatalf("level %s: secret-named colon assignment leaked a value suffix\nkey=%q value=%q suffix=%q\nin=%q\nout=%q", level, key, val, suffix, in, out)
					}
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

// leakedDelimiterSuffix reports a suffix of val that begins at a closing
// delimiter, carries actual content, and still appears in haystack. The value
// extent used to stop at such a delimiter, so a partial leak always takes this
// shape; searching only for the whole value could not see it.
//
// A suffix made up entirely of closing delimiters is not treated as a leak.
// Handing back a trailing run of closers is the documented cost of keeping
// surrounding structure intact - "args=[API_KEY=<redacted>]" and
// `{"args":["API_KEY=<redacted>"]}` both depend on it - and such a run carries
// punctuation rather than secret content. Distinguishing structure from content
// exactly would need the position of the opening delimiter, which only becomes
// available once the assignment rules scan by index.
func leakedDelimiterSuffix(val, haystack string) string {
	const minLeak = 6
	for i := 0; i+minLeak <= len(val); i++ {
		if strings.IndexByte(valueClosers, val[i]) == -1 {
			continue
		}
		suffix := val[i:]
		if strings.TrimLeft(suffix, valueClosers) == "" {
			continue
		}
		if strings.Contains(haystack, suffix) {
			return suffix
		}
	}
	return ""
}
