package env

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCollector_MissingEnv(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".env.example"), []byte("DATABASE_URL=\nAPI_KEY=\n"), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Status != schema.CollectorOK {
		t.Errorf("status = %s, want ok", res.Status)
	}

	var hasMissing bool
	for _, ev := range res.Evidence {
		if ev.Source == ".env" && ev.Value == "missing" {
			hasMissing = true
		}
	}
	if !hasMissing {
		t.Error("expected .env missing evidence")
	}
}

func TestCollector_MissingKeys(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".env.example"), []byte("DATABASE_URL=\nAPI_KEY=\nSECRET=\n"), 0644)
	os.WriteFile(filepath.Join(dir, ".env"), []byte("DATABASE_URL=postgres://localhost/db\n"), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	var hasMissingKeys bool
	for _, ev := range res.Evidence {
		if ev.Source == "missing_keys" {
			hasMissingKeys = true
			if ev.Value != "API_KEY, SECRET" {
				t.Errorf("missing keys = %q, want API_KEY, SECRET", ev.Value)
			}
		}
	}
	if !hasMissingKeys {
		t.Error("expected missing_keys evidence")
	}
}

func TestParseEnvFileKeys(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"KEY=value\n", []string{"KEY"}},
		{"EMPTY=\n", []string{"EMPTY"}},
		{"QUOTED=\"abc def\"\n", []string{"QUOTED"}},
		{"SINGLE='abc def'\n", []string{"SINGLE"}},
		{"VALUE_WITH_EQUALS=a=b=c\n", []string{"VALUE_WITH_EQUALS"}},
		{"export TOKEN=secret\n", []string{"TOKEN"}},
		{"# comment\nKEY=val\n", []string{"KEY"}},
		{"INVALID LINE\nKEY=val\n", []string{"KEY"}},
		{"URL=postgres://user:pass@host:5432/db\n", []string{"URL"}},
	}

	for _, tt := range tests {
		path := filepath.Join(t.TempDir(), ".env")
		os.WriteFile(path, []byte(tt.input), 0644)
		got, err := parseEnvFileKeys(path)
		if err != nil {
			t.Fatalf("parseEnvFileKeys error: %v", err)
		}
		if len(got) != len(tt.want) {
			t.Errorf("parseEnvFileKeys(%q) = %v, want %v", tt.input, got, tt.want)
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("parseEnvFileKeys(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
			}
		}
	}
}

func TestCollector_EnvLocalKeys(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, ".env.example"), []byte("DATABASE_URL=\nAPI_KEY=\n"), 0644)
	os.WriteFile(filepath.Join(dir, ".env.local"), []byte("DATABASE_URL=postgres://localhost/db\n"), 0644)

	c := &Collector{Root: dir}
	res, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}

	var hasLocalMissing bool
	for _, ev := range res.Evidence {
		if ev.Source == "missing_local_keys" {
			hasLocalMissing = true
			if ev.Value != "API_KEY" {
				t.Errorf("missing local keys = %q, want API_KEY", ev.Value)
			}
		}
	}
	if !hasLocalMissing {
		t.Error("expected missing_local_keys evidence")
	}
}
