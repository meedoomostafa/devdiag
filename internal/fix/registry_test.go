package fix

import (
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestRegistryLookup(t *testing.T) {
	r := NewRegistry()

	tests := []struct {
		hintID string
		wantOK bool
	}{
		{"chmod-script", true},
		{"gitignore-env", true},
		{"change-compose-port", true},
		{"stop-service", true},
		{"systemctl-daemon-reload", true},
		{"check-wd", true},
		{"verify-config-path", true},
		{"check-parent-permissions", true},
		{"check-file-owner", true},
		{"start-service", true},
		{"verify-port", true},
		{"verify-service-listening", true},
		{"verify-unix-socket", true},
		{"compose-up", true},
		{"check-nvidia-driver", true},
		{"unknown", false},
	}
	for _, tt := range tests {
		t.Run(tt.hintID, func(t *testing.T) {
			tmpl, ok := r.Lookup(tt.hintID)
			if ok != tt.wantOK {
				t.Fatalf("Lookup(%q) ok = %v, want %v", tt.hintID, ok, tt.wantOK)
			}
			if ok && tmpl.HintID != tt.hintID {
				t.Fatalf("Lookup(%q) HintID = %q, want %q", tt.hintID, tmpl.HintID, tt.hintID)
			}
		})
	}
}

func TestRegistryClasses(t *testing.T) {
	r := NewRegistry()

	tests := []struct {
		hintID    string
		wantClass schema.FixClass
	}{
		{"chmod-script", schema.FixSafe},
		{"gitignore-env", schema.FixManual},
		{"change-compose-port", schema.FixManual},
		{"stop-service", schema.FixManual},
		{"systemctl-daemon-reload", schema.FixGuarded},
		{"suggest-docker-group", schema.FixManual},
		{"add-env-placeholder", schema.FixManual},
		{"install-nvidia-driver", schema.FixManual},
		{"install-cuda-toolkit", schema.FixManual},
		{"install-pytorch-cuda", schema.FixManual},
		{"fix-cache-permissions", schema.FixManual},
		{"warn-docker-cleanup", schema.FixManual},
		{"check-wd", schema.FixManual},
		{"verify-config-path", schema.FixManual},
		{"check-parent-permissions", schema.FixManual},
		{"check-file-owner", schema.FixManual},
		{"start-service", schema.FixManual},
		{"verify-port", schema.FixManual},
		{"verify-service-listening", schema.FixManual},
		{"verify-unix-socket", schema.FixManual},
		{"compose-up", schema.FixGuarded},
	}
	for _, tt := range tests {
		t.Run(tt.hintID, func(t *testing.T) {
			tmpl, ok := r.Lookup(tt.hintID)
			if !ok {
				t.Fatalf("Lookup(%q) not found", tt.hintID)
			}
			if tmpl.Class != tt.wantClass {
				t.Fatalf("Lookup(%q) Class = %q, want %q", tt.hintID, tmpl.Class, tt.wantClass)
			}
		})
	}
}

func TestBindTemplate(t *testing.T) {
	tmpl := Template{
		HintID:   "chmod-script",
		Bin:      "chmod",
		Args:     []string{"+x", "{{path}}"},
		Rollback: []string{"chmod", "-x", "{{path}}"},
	}
	args, rollback, err := BindTemplate(tmpl, map[string]string{"path": "/repo/script.sh"})
	if err != nil {
		t.Fatalf("BindTemplate error: %v", err)
	}
	if len(args) != 2 || args[0] != "+x" || args[1] != "/repo/script.sh" {
		t.Fatalf("unexpected args: %v", args)
	}
	if len(rollback) != 3 || rollback[2] != "/repo/script.sh" {
		t.Fatalf("unexpected rollback: %v", rollback)
	}
}

func TestBindTemplateMissingPlaceholder(t *testing.T) {
	tmpl := Template{
		HintID: "chmod-script",
		Bin:    "chmod",
		Args:   []string{"+x", "{{path}}"},
	}
	_, _, err := BindTemplate(tmpl, map[string]string{})
	if err == nil {
		t.Fatal("expected error for unbound placeholder")
	}
}

func TestBlockedTemplate(t *testing.T) {
	r := &Registry{templates: make(map[string]Template)}
	r.register(Template{
		HintID: "evil-rm",
		Title:  "Bad",
		Bin:    "rm",
		Args:   []string{"-rf", "/"},
	})
	tmpl, ok := r.Lookup("evil-rm")
	if !ok {
		t.Fatal("expected template to be registered")
	}
	if tmpl.Class != schema.FixBlocked {
		t.Fatalf("expected blocked class, got %q", tmpl.Class)
	}
}

func TestBlockedTemplateShellInterpreters(t *testing.T) {
	for _, shell := range []string{"sh", "bash", "zsh", "dash", "ksh", "/bin/sh", "/usr/bin/bash"} {
		r := &Registry{templates: make(map[string]Template)}
		r.register(Template{
			HintID: "shell-wrap",
			Title:  "Shell wrapper",
			Bin:    shell,
			Args:   []string{"-c", "echo hi"},
		})
		tmpl, _ := r.Lookup("shell-wrap")
		if tmpl.Class != schema.FixBlocked {
			t.Errorf("bin %q: expected blocked class, got %q", shell, tmpl.Class)
		}
	}
}

func TestBlockedTemplateSplitArgComposition(t *testing.T) {
	// Dangerous pattern split across separate args must still be caught:
	// no single arg contains "rm -rf", but the joined command does.
	r := &Registry{templates: make(map[string]Template)}
	r.register(Template{
		HintID: "split-danger",
		Title:  "Split danger",
		Bin:    "find",
		Args:   []string{"/data", "-exec", "rm", "-rf", "{}", ";"},
	})
	tmpl, _ := r.Lookup("split-danger")
	if tmpl.Class != schema.FixBlocked {
		t.Errorf("expected blocked class for split rm -rf composition, got %q", tmpl.Class)
	}

	r2 := &Registry{templates: make(map[string]Template)}
	r2.register(Template{
		HintID:   "split-rollback-danger",
		Title:    "Split rollback danger",
		Bin:      "true",
		Rollback: []string{"rm", "-rf", "/tmp/x"},
	})
	tmpl2, _ := r2.Lookup("split-rollback-danger")
	if tmpl2.Class != schema.FixBlocked {
		t.Errorf("expected blocked class for split rollback composition, got %q", tmpl2.Class)
	}
}

func TestIsBlockedCommandSplitArgs(t *testing.T) {
	if !IsBlockedCommand("find", []string{"/data", "-exec", "rm", "-rf", "{}", ";"}) {
		t.Error("expected split rm -rf args to be blocked at runtime")
	}
	if !IsBlockedCommand("bash", []string{"-c", "echo hi"}) {
		t.Error("expected shell interpreter to be blocked at runtime")
	}
	if IsBlockedCommand("chmod", []string{"+x", "script.sh"}) {
		t.Error("chmod +x must not be blocked")
	}
	if IsBlockedCommand("docker", []string{"compose", "up", "-d"}) {
		t.Error("docker compose up must not be blocked")
	}
}
