package redact

import (
	"strings"
	"testing"
)

const pemBody = "MIIEowIBAAKCAQEA7f9xQmVerySecretKeyMaterialHere0000000000000000"

// TestBlockScalarSecretsAreMasked pins the YAML block-scalar contract at the
// default redaction level. Multi-line values are how private keys actually
// reach a repository (k8s Secret stringData, Actions env, compose, Ansible,
// Helm values), and before this rule existed the block indicator was masked
// while every indented continuation line was emitted verbatim.
func TestBlockScalarSecretsAreMasked(t *testing.T) {
	tests := []struct {
		name       string
		in         string
		mustGone   []string
		mustRemain []string
	}{
		{
			name:       "pipe block with pem body",
			in:         "private_key: |\n  -----BEGIN RSA PRIVATE KEY-----\n  " + pemBody + "\n  -----END RSA PRIVATE KEY-----\n",
			mustGone:   []string{pemBody, "BEGIN RSA PRIVATE KEY"},
			mustRemain: []string{"private_key", "<redacted>"},
		},
		{
			name:     "strip chomping indicator",
			in:       "api_token: |-\n  " + pemBody + "\n",
			mustGone: []string{pemBody},
		},
		{
			name:     "keep chomping indicator",
			in:       "api_token: |+\n  " + pemBody + "\n",
			mustGone: []string{pemBody},
		},
		{
			name:     "folded block",
			in:       "client_secret: >\n  " + pemBody + "\n",
			mustGone: []string{pemBody},
		},
		{
			name:     "folded strip",
			in:       "client_secret: >-\n  " + pemBody + "\n",
			mustGone: []string{pemBody},
		},
		{
			name:     "explicit indent indicator",
			in:       "password: |2\n  " + pemBody + "\n",
			mustGone: []string{pemBody},
		},
		{
			name:     "chomp then indent indicator",
			in:       "password: |-2\n  " + pemBody + "\n",
			mustGone: []string{pemBody},
		},
		{
			name:     "indent then chomp indicator",
			in:       "password: |2-\n  " + pemBody + "\n",
			mustGone: []string{pemBody},
		},
		{
			name:     "trailing comment after indicator",
			in:       "private_key: | # inline note\n  " + pemBody + "\n",
			mustGone: []string{pemBody},
		},
		{
			name:     "blank line inside block",
			in:       "private_key: |\n  first" + pemBody + "\n\n  second" + pemBody + "\n",
			mustGone: []string{"first" + pemBody, "second" + pemBody},
		},
		{
			name:     "crlf line endings",
			in:       "private_key: |\r\n  " + pemBody + "\r\n",
			mustGone: []string{pemBody},
		},
		{
			name:     "no trailing newline",
			in:       "private_key: |\n  " + pemBody,
			mustGone: []string{pemBody},
		},
		{
			name:       "block terminates at dedent",
			in:         "private_key: |\n  " + pemBody + "\nimage: nginx:1.25\n",
			mustGone:   []string{pemBody},
			mustRemain: []string{"image: nginx:1.25"},
		},
		{
			// sol-architect CRITICAL: in a compact sequence entry the body can
			// be indented to the key's own column, so the threshold must come
			// from the containing line's indentation, not the key column.
			name:       "sequence entry body at key column",
			in:         "items:\n- private_key: |\n  " + pemBody + "\n- name: next\n",
			mustGone:   []string{pemBody},
			mustRemain: []string{"- name: next"},
		},
		{
			// sol-secops attack input: YAML forbids tab indentation, but the
			// scanner ingests arbitrary text and must fail toward redaction.
			name:     "tab indented body",
			in:       "private_key: |\n\t" + pemBody + "\n",
			mustGone: []string{pemBody},
		},
		{
			name:       "kubernetes secret stringdata",
			in:         "stringData:\n  tls.key: |\n    " + pemBody + "\n  tls.crt: |\n    -----BEGIN CERTIFICATE-----\n",
			mustGone:   []string{pemBody},
			mustRemain: []string{"tls.crt"},
		},
		{
			// sol-secops: a benign key name must not defeat the rule when the
			// body is unmistakably private key material.
			name:     "benign key name with pem private key body",
			in:       "data: |\n  -----BEGIN OPENSSH PRIVATE KEY-----\n  " + pemBody + "\n",
			mustGone: []string{pemBody},
		},
		{
			// Certificates are public. Masking them destroys diagnostic value
			// with no confidentiality gain.
			name:       "certificate only block is preserved",
			in:         "ca_cert_file: |\n  -----BEGIN CERTIFICATE-----\n  MIIC0zCCAbugAwIBAgIUdiagnosticpubliccertdata000000\n",
			mustRemain: []string{"BEGIN CERTIFICATE", "MIIC0zCCAbugAwIBAgIUdiagnosticpubliccertdata000000"},
		},
		{
			name:       "non secret key block is preserved",
			in:         "description: |\n  This project builds a diagnostic CLI.\n  Second line of prose.\n",
			mustRemain: []string{"This project builds a diagnostic CLI.", "Second line of prose."},
		},
		{
			name:       "json pipe value is not a block indicator",
			in:         "{\"separator\": \"|\", \"image\": \"nginx\"}\n",
			mustRemain: []string{"nginx"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := NewEngine(LevelDefault)
			out := e.RedactString(tc.in, "test")

			for _, gone := range tc.mustGone {
				if strings.Contains(out, gone) {
					t.Errorf("leaked %q\nin:\n%s\nout:\n%s", gone, tc.in, out)
				}
			}
			for _, remain := range tc.mustRemain {
				if !strings.Contains(out, remain) {
					t.Errorf("expected %q to survive\nin:\n%s\nout:\n%s", remain, tc.in, out)
				}
			}
			// The engine-wide invariant, asserted per case so a regression
			// names the shape that broke it.
			if again := e.RedactString(out, "test"); again != out {
				t.Errorf("not idempotent\nonce:\n%s\ntwice:\n%s", out, again)
			}
		})
	}
}

// TestDottedAndDashedSecretKeyNames pins segment separators in the key-name
// classifier. Kubernetes TLS secrets (tls.key), Helm values, and Java-style
// property names use "." and "-" where env vars use "_", and the classifier
// only recognised "_", so tls.key survived with its value intact on a single
// line as well as in a block scalar.
func TestDottedAndDashedSecretKeyNames(t *testing.T) {
	secret := []string{
		"tls.key",
		"tls-key",
		"ssh.private-key",
		"service.account.key",
		"app-auth-token",
		"db.password",
	}
	for _, key := range secret {
		if !IsSecretKeyName(key) {
			t.Errorf("IsSecretKeyName(%q) = false, want true", key)
		}
	}

	// Must not start matching words that merely contain a keyword.
	notSecret := []string{
		"monkey.data",
		"author.name",
		"keyboard-layout",
		"oauth-enabled",
		"exit.code",
	}
	for _, key := range notSecret {
		if IsSecretKeyName(key) {
			t.Errorf("IsSecretKeyName(%q) = true, want false", key)
		}
	}
}

// TestDottedSecretKeyLeaksSingleLine is the single-line half of the same
// defect: the block-scalar rule is not what saves this shape.
func TestDottedSecretKeyLeaksSingleLine(t *testing.T) {
	e := NewEngine(LevelDefault)
	out := e.RedactString("tls.key: LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t\n", "test")
	if strings.Contains(out, "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t") {
		t.Errorf("dotted secret key leaked its value: %s", out)
	}
}

// TestPEMPrivateKeyBlocksAreMasked covers PEM key material that arrives with
// no surrounding structure at all, which is what "cat id_rsa" or "kubectl get
// secret -o yaml | base64 -d" produces. Before this rule only strict mode
// caught it, via the incidental 40-plus character token rule, so the default
// level shipped whole private keys into repro.json and capsule logs.
func TestPEMPrivateKeyBlocksAreMasked(t *testing.T) {
	const body = "MIIEowIBAAKCAQEABAREPEMcanary000000000000000000000000000"

	tests := []struct {
		name       string
		in         string
		mustGone   []string
		mustRemain []string
	}{
		{
			name:     "complete rsa key block",
			in:       "-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n-----END RSA PRIVATE KEY-----\n",
			mustGone: []string{body, "BEGIN RSA PRIVATE KEY"},
		},
		{
			name:     "openssh key block",
			in:       "-----BEGIN OPENSSH PRIVATE KEY-----\n" + body + "\n-----END OPENSSH PRIVATE KEY-----\n",
			mustGone: []string{body},
		},
		{
			name:     "unlabelled private key",
			in:       "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----\n",
			mustGone: []string{body},
		},
		{
			name:     "pgp private key block",
			in:       "-----BEGIN PGP PRIVATE KEY BLOCK-----\n" + body + "\n-----END PGP PRIVATE KEY BLOCK-----\n",
			mustGone: []string{body},
		},
		{
			// Fail closed: a truncated key must not survive because the END
			// marker never arrived.
			name:     "unterminated key block",
			in:       "-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n",
			mustGone: []string{body},
		},
		{
			name:       "surrounding diagnostics survive",
			in:         "reading key file\n-----BEGIN RSA PRIVATE KEY-----\n" + body + "\n-----END RSA PRIVATE KEY-----\ndone in 12ms\n",
			mustGone:   []string{body},
			mustRemain: []string{"reading key file", "done in 12ms"},
		},
		{
			// Certificates are public: masking them costs diagnostic value
			// for no confidentiality gain.
			name:       "certificate block is preserved",
			in:         "-----BEGIN CERTIFICATE-----\nMIIC0zCCAbugAwIBAgIUPUBLICcertdata0000000\n-----END CERTIFICATE-----\n",
			mustRemain: []string{"BEGIN CERTIFICATE", "MIIC0zCCAbugAwIBAgIUPUBLICcertdata0000000"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := NewEngine(LevelDefault)
			out := e.RedactString(tc.in, "test")
			for _, gone := range tc.mustGone {
				if strings.Contains(out, gone) {
					t.Errorf("leaked %q\nout:\n%s", gone, out)
				}
			}
			for _, remain := range tc.mustRemain {
				if !strings.Contains(out, remain) {
					t.Errorf("expected %q to survive\nout:\n%s", remain, out)
				}
			}
			if again := e.RedactString(out, "test"); again != out {
				t.Errorf("not idempotent\nonce:\n%s\ntwice:\n%s", out, again)
			}
		})
	}
}

// TestExoticWhitespaceAroundAssignment pins the whitespace class used by the
// assignment rule family. Go's \s omits the vertical tab, NEL, and NBSP while
// strings.TrimSpace - and so the key classifier - treats them as space, so
// "KEY\v=secret" was classified as a secret assignment and then missed by
// every rule that could have masked it. Found by FuzzRedactString.
func TestExoticWhitespaceAroundAssignment(t *testing.T) {
	const secret = "hunter2secret"
	for _, sep := range []struct{ name, ch string }{
		{"vertical tab", "\v"},
		{"next line", "\u0085"},
		{"non breaking space", "\u00a0"},
		{"tab", "\t"},
		{"space", " "},
	} {
		t.Run(sep.name, func(t *testing.T) {
			e := NewEngine(LevelDefault)
			in := "API_TOKEN" + sep.ch + "=" + secret
			out := e.RedactString(in, "test")
			if strings.Contains(out, secret) {
				t.Errorf("leaked value across %s separator: in=%q out=%q", sep.name, in, out)
			}
			if again := e.RedactString(out, "test"); again != out {
				t.Errorf("not idempotent: once=%q twice=%q", out, again)
			}
		})
	}
}

// TestBracketLeadingSecretValue pins the unquoted value extent. The value
// class excludes "]" so that Go slice-formatted arguments keep their closing
// bracket, which meant a secret whose first character was "]" matched an
// empty value and survived untouched. Found by FuzzRedactString.
func TestBracketLeadingSecretValue(t *testing.T) {
	e := NewEngine(LevelDefault)

	// The leak: a value whose first character is a delimiter must be masked.
	// Each of these matched an empty value extent and survived untouched.
	for _, lead := range []string{"]", "`", "'", "\""} {
		secret := lead + "00000secret"
		out := e.RedactString("API_TOKEN="+secret, "test")
		if strings.Contains(out, secret) {
			t.Errorf("delimiter-leading secret leaked (lead=%q): %q", lead, out)
		}
	}

	// The behaviour that must not regress: a trailing bracket still bounds
	// the value, so slice-formatted log lines stay readable.
	if out := e.RedactString("args=[API_KEY=secret1]", "test"); !strings.Contains(out, "]") {
		t.Errorf("closing bracket was consumed: %q", out)
	}
}

// TestColonQuotedValueTrailingCharacter pins idempotence for a colon-assigned
// quoted value followed by a stray character. The quoted branch used to stop
// at the closing quote, so the first pass left "<redacted>0" behind and the
// second pass masked it again. Found by FuzzRedactString.
func TestColonQuotedValueTrailingCharacter(t *testing.T) {
	e := NewEngine(LevelDefault)
	for _, in := range []string{
		"token:\"\"0",
		"token: \"abc\"trailing",
		"password:''x",
	} {
		out := e.RedactString(in, "test")
		if again := e.RedactString(out, "test"); again != out {
			t.Errorf("not idempotent for %q\nonce=%q\ntwice=%q", in, out, again)
		}
	}

	// Flow delimiters must still bound the value so surrounding structure and
	// sibling entries survive.
	out := e.RedactString(`{"token": "abc", "image": "nginx"}`, "test")
	for _, want := range []string{"<redacted>", `"image": "nginx"`} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in %q", want, out)
		}
	}
	if strings.Contains(out, "abc") {
		t.Errorf("token value leaked: %q", out)
	}
}
