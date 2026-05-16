package redact

import (
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
	e := NewEngine(LevelDefault)
	input := "/home/medo/.config/devdiag/settings.json"
	got := e.RedactString(input, "path")
	if got == input {
		t.Errorf("RedactString() did not redact home dir: %q", got)
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
