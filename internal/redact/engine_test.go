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
		"env_values",
		"secret_key_values",
		"cli_secret_flags",
		"quoted_key_material",
		"url_credentials",
		"bearer_tokens",
		"jwt_tokens",
		"home_directory",
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
