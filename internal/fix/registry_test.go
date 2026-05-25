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
