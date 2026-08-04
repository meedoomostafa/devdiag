package redact

import (
	"strings"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestRedactString_URL(t *testing.T) {
	e := NewEngine(LevelDefault)
	input := "DATABASE_URL=postgres://user:secretpassword@localhost:5432/app"
	got := e.RedactString(input, "env")
	// Env redaction runs before URL redaction, so the entire value is redacted.
	want := "DATABASE_URL=<redacted>"
	if got != want {
		t.Errorf("RedactString() = %q, want %q", got, want)
	}
}

func TestRedactString_GitRemote(t *testing.T) {
	e := NewEngine(LevelDefault)
	input := "https://user:token@github.com/meedoomostafa/devdiag.git"
	got := e.RedactString(input, "git_remote")
	want := "https://user:<redacted>@github.com/meedoomostafa/devdiag.git"
	if got != want {
		t.Errorf("RedactString() = %q, want %q", got, want)
	}
}

func TestRedactString_HomeDir(t *testing.T) {
	if homeDir == "" {
		t.Skip("HOME is not set")
	}
	e := NewEngine(LevelDefault)
	input := homeDir + "/.config/devdiag/settings.json"
	got := e.RedactString(input, "path")
	want := "~/.config/devdiag/settings.json"
	if got != want {
		t.Errorf("RedactString() = %q, want %q", got, want)
	}
}

func TestRedactString_Off(t *testing.T) {
	e := NewEngine(LevelOff)
	input := "DATABASE_URL=postgres://user:secret@localhost:5432/app"
	got := e.RedactString(input, "env")
	if got != input {
		t.Errorf("RedactString(off) modified string: %q", got)
	}
}

func TestRedactString_Empty(t *testing.T) {
	e := NewEngine(LevelDefault)
	got := e.RedactString("", "env")
	if got != "" {
		t.Errorf("RedactString(\"\") = %q, want empty", got)
	}
}

func TestRedactString_EnvWithColon(t *testing.T) {
	e := NewEngine(LevelDefault)
	input := "PATH=/usr/bin:/bin:/opt/bin"
	got := e.RedactString(input, "env")
	want := "PATH=<redacted>"
	if got != want {
		t.Errorf("RedactString() = %q, want %q", got, want)
	}
}

func TestRedactString_MultilineEnvValues(t *testing.T) {
	e := NewEngine(LevelDefault)
	input := "API_KEY=secret123\nERR_TOKEN=secret456\nplain line"
	got := e.RedactString(input, "log")
	if got != "API_KEY=<redacted>\nERR_TOKEN=<redacted>\nplain line" {
		t.Errorf("RedactString() = %q", got)
	}
}

func TestRedactString_QuotedEnvValues(t *testing.T) {
	e := NewEngine(LevelDefault)
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "single quoted shell argument",
			input: "printf 'API_KEY=secret123'",
			want:  "printf 'API_KEY=<redacted>'",
		},
		{
			name:  "double quoted shell argument",
			input: `printf "API_KEY=secret123"`,
			want:  `printf "API_KEY=<redacted>"`,
		},
		{
			name:  "json quoted value",
			input: `{"args":["API_KEY=secret123"]}`,
			want:  `{"args":["API_KEY=<redacted>"]}`,
		},
		{
			name:  "go slice argument",
			input: `args=[API_KEY=secret123]`,
			want:  `args=[API_KEY=<redacted>]`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.RedactString(tt.input, "agent_run")
			if got != tt.want {
				t.Errorf("RedactString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRedactString_QuotedEnvValueAssignments(t *testing.T) {
	e := NewEngine(LevelDefault)
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "double quoted value with spaces",
			input: `DB_PASSWORD="my secret pass"`,
			want:  "DB_PASSWORD=<redacted>",
		},
		{
			name:  "single quoted value with spaces",
			input: "DB_PASSWORD='hunter2 extra'",
			want:  "DB_PASSWORD=<redacted>",
		},
		{
			name:  "export with double quoted value",
			input: `export TOKEN="abc def"`,
			want:  "export TOKEN=<redacted>",
		},
		{
			name:  "quoted value inside log line",
			input: `compose error: SECRET_KEY="s3cr3t value" is invalid`,
			want:  "compose error: SECRET_KEY=<redacted> is invalid",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.RedactString(tt.input, "collector_note")
			if got != tt.want {
				t.Errorf("RedactString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRedactString_DoesNotRedactLowercaseDiagnostics(t *testing.T) {
	e := NewEngine(LevelDefault)
	for _, input := range []string{"exit_code=1", "status=ok", "duration_ms=42", "collector=env"} {
		got := e.RedactString(input, "log")
		if got != input {
			t.Errorf("RedactString(%q) = %q, want unchanged", input, got)
		}
	}
}

func TestRedactString_LowercaseSecretBearingKeys(t *testing.T) {
	e := NewEngine(LevelDefault)
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"lowercase password key", "db_password=lowercase123", "db_password=<redacted>"},
		{"lowercase secret key", "client_secret=shh123", "client_secret=<redacted>"},
		{"lowercase token key", "auth_token=abc.def", "auth_token=<redacted>"},
		{"lowercase api_key", "api_key=xyz789", "api_key=<redacted>"},
		{"mixed case key", "Db_Password=hunter2", "Db_Password=<redacted>"},
		{"quoted lowercase value", `db_password="my secret"`, "db_password=<redacted>"},
		{"inside log line", "connect failed: passwd=root123 refused", "connect failed: passwd=<redacted> refused"},
		{"auth_code key", "auth_code=xyz42", "auth_code=<redacted>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.RedactString(tt.input, "log")
			if got != tt.want {
				t.Errorf("RedactString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRedactString_DoesNotRedactAuthLikeWords(t *testing.T) {
	e := NewEngine(LevelDefault)
	tests := []struct {
		name  string
		input string
	}{
		{"author key", "author=Jane"},
		{"authority key", "authority=government"},
		{"authentication key", "authentication=enabled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.RedactString(tt.input, "log")
			if got != tt.input {
				t.Errorf("RedactString(%q) = %q, want unchanged", tt.input, got)
			}
		})
	}
}

func TestRedactString_StrictRedactsHexTokens(t *testing.T) {
	e := NewEngine(LevelStrict)
	input := "commit abcd1234abcd1234abcd1234abcd1234abcd1234 found"
	got := e.RedactString(input, "log")
	if got == input {
		t.Errorf("strict mode did not redact hex token: %q", got)
	}
}

func TestRedactString_DefaultDoesNotRedactHexTokens(t *testing.T) {
	e := NewEngine(LevelDefault)
	input := "commit abcd1234abcd1234abcd1234abcd1234abcd1234 found"
	got := e.RedactString(input, "log")
	if got != input {
		t.Errorf("default mode incorrectly redacted hex token: %q", got)
	}
}

func TestRedactString_DefaultRedactsQuotedKeyMaterialFromToolErrors(t *testing.T) {
	e := NewEngine(LevelDefault)
	input := `docker compose config failed: failed to read .env: line 65: unexpected character "/" in variable name "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoXLZ1K/ecjzUBJyQ41WD"`
	got := e.RedactString(input, "collector_note")
	if got == input {
		t.Fatalf("default mode did not redact quoted key material: %q", got)
	}
	if got != `docker compose config failed: failed to read .env: line 65: unexpected character "/" in variable name "<token>"` {
		t.Fatalf("RedactString() = %q", got)
	}
}

func TestRedactString_BearerTokens(t *testing.T) {
	e := NewEngine(LevelDefault)
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "authorization header",
			input: "Authorization: Bearer abc123def456ghi789jkl012mno345pqr678",
			want:  "Authorization: Bearer <redacted>",
		},
		{
			name:  "lowercase bearer",
			input: "authorization: bearer sk-live-0123456789abcdef",
			want:  "authorization: bearer <redacted>",
		},
		{
			name:  "bearer inside curl error log",
			input: `curl -H "Authorization: Bearer tok_secret.value-123" failed`,
			want:  `curl -H "Authorization: Bearer <redacted>" failed`,
		},
		{
			name:  "bearer JWT still redacts",
			input: "Bearer eyJhbGciOi.eyJzdWIi.SflKxwRJ",
			want:  "Bearer <redacted>",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.RedactString(tt.input, "collector_note")
			if got != tt.want {
				t.Errorf("RedactString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRedactReport_DoesNotMutateOriginal(t *testing.T) {
	e := NewEngine(LevelDefault)
	original := &schema.Report{
		Findings: []schema.Finding{
			{
				Title: "Issue with postgres://user:pass@host/db",
				Evidence: []schema.Evidence{
					{Source: "env", Value: "SECRET_KEY=abc123"},
				},
			},
		},
	}
	redacted := e.RedactReport(original)
	if redacted.Findings[0].Title == original.Findings[0].Title {
		t.Error("RedactReport did not redact the finding title")
	}
	if redacted.Findings[0].Evidence[0].Value == original.Findings[0].Evidence[0].Value {
		t.Error("RedactReport did not redact evidence value")
	}
	if redacted == original {
		t.Error("RedactReport returned the same pointer, expected a copy")
	}
}

func TestRedactReport_RedactsReproMapRecursively(t *testing.T) {
	e := NewEngine(LevelDefault)
	report := &schema.Report{
		Repro: map[string]interface{}{
			"command": "API_KEY=secret123",
			"env": map[string]interface{}{
				"URL": "https://user:password@github.com",
			},
			"args": []interface{}{
				"PASSWORD=secret789",
			},
			"ok": true,
		},
	}

	redacted := e.RedactReport(report)
	repro := redacted.Repro

	if strings.Contains(repro["command"].(string), "secret") {
		t.Error("Repro command not redacted")
	}
	env := repro["env"].(map[string]interface{})
	if strings.Contains(env["URL"].(string), "password") {
		t.Errorf("Repro env value not redacted: %v", env["URL"])
	}
	args := repro["args"].([]interface{})
	if strings.Contains(args[0].(string), "secret") {
		t.Error("Repro args value not redacted")
	}
	if repro["ok"] != true {
		t.Error("Boolean value in repro map mutated")
	}
}

func TestRedactReport_RedactsReproMapRecursively_Guaranteed(t *testing.T) {
	e := NewEngine(LevelDefault)
	report := &schema.Report{
		Repro: map[string]interface{}{
			"env": map[string]interface{}{
				"URL": "https://user:password@github.com",
			},
		},
	}
	redacted := e.RedactReport(report)
	env := redacted.Repro["env"].(map[string]interface{})
	if strings.Contains(env["URL"].(string), "password") {
		t.Errorf("Guaranteed repro env value not redacted: %v", env["URL"])
	}
}

func TestRedactString_CLISecrets(t *testing.T) {
	e := NewEngine(LevelDefault)
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"--password=secret", "cmd --password=secret", "cmd --password=<redacted>"},
		{"--password secret", "cmd --password secret", "cmd --password <redacted>"},
		{"--token=secret", "cmd --token=abc123", "cmd --token=<redacted>"},
		{"--api-key=secret", "cmd --api-key=xyz789", "cmd --api-key=<redacted>"},
		{"--client-secret secret", "cmd --client-secret shh", "cmd --client-secret <redacted>"},
		{"--Password=SECRET (upper)", "cmd --Password=SECRET", "cmd --Password=<redacted>"},
		{"--API-KEY=secret (upper)", "cmd --API-KEY=topsecret", "cmd --API-KEY=<redacted>"},
		{"--auth-token=secret", "cmd --auth-token=BearerXYZ", "cmd --auth-token=<redacted>"},
		{"multiple secrets", "cmd --password=p --token=t", "cmd --password=<redacted> --token=<redacted>"},
		{"no false positive on --port", "cmd --port=8080", "cmd --port=8080"},
		{"double quoted value with spaces", `cmd --password "quoted secret"`, "cmd --password <redacted>"},
		{"single quoted value with spaces", "cmd --token 'multi word token'", "cmd --token <redacted>"},
		{"double quoted value after equals", `cmd --api-key="spaced key value"`, "cmd --api-key=<redacted>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := e.RedactString(tt.input, "repro_args")
			if got != tt.want {
				t.Errorf("RedactString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRuleNames(t *testing.T) {
	def := RuleNames(LevelDefault)
	wantDefault := []string{
		"pem_private_keys",
		"cookie_values",
		"env_values",
		"secret_key_values",
		"cli_secret_flags",
		"secret_named_assignments",
		"interpolation_defaults",
		"quoted_key_material",
		"url_credentials",
		"auth_headers",
		"bearer_tokens",
		"jwt_tokens",
		"home_directory",
		"evidence_secret_sources",
	}
	if len(def) != len(wantDefault) {
		t.Fatalf("RuleNames(default) = %v, want %v", def, wantDefault)
	}
	for i, w := range wantDefault {
		if def[i] != w {
			t.Errorf("RuleNames(default)[%d] = %q, want %q", i, def[i], w)
		}
	}

	strict := RuleNames(LevelStrict)
	if len(strict) != len(wantDefault)+1 || strict[len(strict)-1] != "strict_long_tokens" {
		t.Errorf("RuleNames(strict) = %v, want default rules + strict_long_tokens", strict)
	}

	if off := RuleNames(LevelOff); off != nil {
		t.Errorf("RuleNames(off) = %v, want nil", off)
	}
}

func TestRedactEvidence_SecretSourceKeyMasksBareValue(t *testing.T) {
	e := NewEngine(LevelDefault)
	cases := []struct {
		name   string
		source string
		value  string
		want   string
	}{
		{
			name:   "github job env secret key",
			source: "ci_env__job__scan__AWS_SECRET_ACCESS_KEY",
			value:  "CANARYAWSKEYabcdef1234567890ABCDEF12",
			want:   "<redacted>",
		},
		{
			name:   "gitlab workflow variable token key",
			source: "ci_env__workflow__API_TOKEN",
			value:  "glpat-canary-value",
			want:   "<redacted>",
		},
		{
			name:   "password key",
			source: "ci_env__step__build__2__DB_PASSWORD",
			value:  "hunter2",
			want:   "<redacted>",
		},
		{
			name:   "non-secret key keeps value",
			source: "ci_env__job__scan__NODE_VERSION",
			value:  "20",
			want:   "20",
		},
		{
			name:   "non-secret source with embedded url creds still redacted",
			source: "ci_env__job__scan__SERVICE_URL",
			value:  "https://user:pass@example.com/x",
			want:   "https://user:<redacted>@example.com/x",
		},
		{
			name:   "compact token key without separators",
			source: "ci_env__job__scan__NPMTOKEN",
			value:  "npm-canary",
			want:   "<redacted>",
		},
		{
			name:   "compact github token key",
			source: "ci_env__workflow__GITHUBTOKEN",
			value:  "ghp-canary",
			want:   "<redacted>",
		},
		{
			name:   "private key name via key segment",
			source: "ci_env__job__deploy__PRIVATE_KEY",
			value:  "-----BEGIN CANARY-----",
			want:   "<redacted>",
		},
		{
			name:   "jwt-named key",
			source: "ci_env__job__scan__CI_JOB_JWT_V2",
			value:  "eyJ-canary",
			want:   "<redacted>",
		},
		{
			name:   "escaped double underscore in key still classified",
			source: "ci_env__job__scan__AUTH%5F%5FTOKEN",
			value:  "canary",
			want:   "<redacted>",
		},
		{
			name:   "job named auth outside ci_env namespace keeps value",
			source: "ci_runs_on__auth",
			value:  "ubuntu-latest",
			want:   "ubuntu-latest",
		},
		{
			name:   "author-like key keeps value",
			source: "ci_env__job__scan__AUTHOR",
			value:  "octocat",
			want:   "octocat",
		},
		{
			name:   "oauth enabled flag keeps value",
			source: "ci_env__job__scan__OAUTH_ENABLED",
			value:  "true",
			want:   "true",
		},
		{
			name:   "ssh key standalone segment masked",
			source: "ci_env__job__deploy__SSH_KEY",
			value:  "ssh-canary",
			want:   "<redacted>",
		},
		{
			name:   "deploy key masked",
			source: "ci_env__workflow__DEPLOY_KEY",
			value:  "deploy-canary",
			want:   "<redacted>",
		},
		{
			name:   "keyboard-style name keeps value",
			source: "ci_env__job__scan__KEYBOARD_LAYOUT",
			value:  "qwerty",
			want:   "qwerty",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := e.RedactEvidence(tc.source, tc.value)
			if got != tc.want {
				t.Errorf("RedactEvidence(%q, %q) = %q, want %q", tc.source, tc.value, got, tc.want)
			}
		})
	}
}

func TestRedactEvidence_OffLevelKeepsValue(t *testing.T) {
	e := NewEngine(LevelOff)
	got := e.RedactEvidence("ci_env__job__scan__AWS_SECRET_ACCESS_KEY", "rawvalue")
	if got != "rawvalue" {
		t.Errorf("RedactEvidence(off) = %q, want rawvalue", got)
	}
}

func TestRedactReport_EvidenceWithSecretSourceIsMasked(t *testing.T) {
	e := NewEngine(LevelDefault)
	report := &schema.Report{
		Collectors: []schema.CollectorResult{
			{
				Name: "ci",
				Evidence: []schema.Evidence{
					{Source: "ci_env__job__scan__AWS_SECRET_ACCESS_KEY", Value: "CANARYAWSKEYabcdef1234567890"},
					{Source: "ci_env__job__scan__NODE_VERSION", Value: "20"},
				},
			},
		},
		Findings: []schema.Finding{
			{
				ID: "F-X",
				Evidence: []schema.Evidence{
					{Source: "ci_env__workflow__NPM_TOKEN", Value: "npm-canary-token"},
				},
			},
		},
	}
	redacted := e.RedactReport(report)
	if got := redacted.Collectors[0].Evidence[0].Value; got != "<redacted>" {
		t.Errorf("collector secret evidence = %q, want <redacted>", got)
	}
	if got := redacted.Collectors[0].Evidence[1].Value; got != "20" {
		t.Errorf("collector non-secret evidence = %q, want 20", got)
	}
	if got := redacted.Findings[0].Evidence[0].Value; got != "<redacted>" {
		t.Errorf("finding secret evidence = %q, want <redacted>", got)
	}
}

func TestRedactString_InterpolationDefaults(t *testing.T) {
	e := NewEngine(LevelDefault)
	cases := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "secret-named var default masked",
			input: "services.app.environment references ${API_TOKEN:-CANARYCOMPOSEDEFAULT999}",
			want:  "services.app.environment references ${API_TOKEN:-<redacted>}",
		},
		{
			name:  "password var with dash default",
			input: "db.env references ${DB_PASSWORD-supersecret}",
			want:  "db.env references ${DB_PASSWORD-<redacted>}",
		},
		{
			name:  "non-secret var default kept",
			input: "app.env references ${NODE_VERSION:-20}",
			want:  "app.env references ${NODE_VERSION:-20}",
		},
		{
			name:  "no default unchanged",
			input: "app.env references ${API_TOKEN}",
			want:  "app.env references ${API_TOKEN}",
		},
		{
			name:  "nested default masked through matching brace",
			input: "app.env references ${A_TOKEN:-${B}-real-secret}",
			want:  "app.env references ${A_TOKEN:-<redacted>}",
		},
		{
			name:  "author var default kept",
			input: "app.env references ${AUTHOR:-someone}",
			want:  "app.env references ${AUTHOR:-someone}",
		},
		{
			name:  "oauth enabled flag default kept",
			input: "app.env references ${OAUTH_ENABLED:-true}",
			want:  "app.env references ${OAUTH_ENABLED:-true}",
		},
		{
			name:  "empty default unchanged",
			input: "app.env references ${API_TOKEN:-}",
			want:  "app.env references ${API_TOKEN:-}",
		},
		{
			name:  "unbalanced interpolation left intact",
			input: "app.env references ${API_TOKEN:-broken",
			want:  "app.env references ${API_TOKEN:-broken",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := e.RedactString(tc.input, "collector_evidence")
			if got != tc.want {
				t.Errorf("RedactString(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestRedactString_SecretNamedAssignmentsMatchSourceClassifier pins that the
// content classifier and the evidence-source classifier agree on what counts
// as a secret key name. They drifted once: batch D1 taught the source
// classifier about standalone key/auth segments (SSH_KEY, DEPLOY_KEY) while
// the content rules still only knew api_key, so a mixed-case sshKey=... in a
// log line survived redaction. Found by FuzzRedactString.
func TestRedactString_SecretNamedAssignmentsMatchSourceClassifier(t *testing.T) {
	e := NewEngine(LevelDefault)
	redacted := []string{
		"sshKey=abc123",
		"deployKey=xyz789",
		"signing_key=material",
		"Key=x",
		"keY=hunter2",
		"myAuth=bearer-ish",
	}
	for _, in := range redacted {
		got := e.RedactString(in, "log")
		key, _, _ := strings.Cut(in, "=")
		if !strings.Contains(got, "<redacted>") {
			t.Errorf("RedactString(%q) = %q, want the value redacted (key %q is secret-named)", in, got, key)
		}
	}

	// Benign diagnostics must still survive: the classifier anchors key and
	// auth as whole segments, so these are not secret-named.
	kept := []string{"exit_code=1", "status=ok", "duration_ms=42", "collector=env", "monkey=banana", "keyboard=us"}
	for _, in := range kept {
		if got := e.RedactString(in, "log"); got != in {
			t.Errorf("RedactString(%q) = %q, want unchanged", in, got)
		}
	}
}
