package session

import (
	"strings"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/remote/target"
)

func TestGenerateID(t *testing.T) {
	id := GenerateID()
	if id == "" {
		t.Fatal("GenerateID returned empty string")
	}
	if strings.Contains(id, "..") || strings.Contains(id, "/") || strings.Contains(id, "\\") {
		t.Fatalf("GenerateID returned unsafe characters: %q", id)
	}
	// Format should be YYYYMMDDT...Z_hex
	if !strings.Contains(id, "_") {
		t.Fatalf("GenerateID missing underscore separator: %q", id)
	}
	parts := strings.Split(id, "_")
	if len(parts) != 2 {
		t.Fatalf("GenerateID unexpected format: %q", id)
	}
}

func TestSSHRootDir(t *testing.T) {
	dir := SSHRootDir("20260516T203500Z_a19f3c")
	if !strings.Contains(dir, ".devdiag/remote") {
		t.Errorf("SSHRootDir = %q, expected to contain .devdiag/remote", dir)
	}
}

func TestContainerRootDir(t *testing.T) {
	dir := ContainerRootDir("20260516T203500Z_a19f3c")
	if !strings.HasPrefix(dir, "/tmp/devdiag-remote") {
		t.Errorf("ContainerRootDir = %q, expected prefix /tmp/devdiag-remote", dir)
	}
}

func TestShellPath(t *testing.T) {
	if got := ShellPath("~/.devdiag/remote/s1"); got != "$HOME/.devdiag/remote/s1" {
		t.Errorf("ShellPath SSH path = %q, want $HOME/.devdiag/remote/s1", got)
	}
	if got := ShellPath("/tmp/devdiag-remote/s1"); got != "/tmp/devdiag-remote/s1" {
		t.Errorf("ShellPath container path = %q, want /tmp/devdiag-remote/s1", got)
	}
}

func TestShellQuote(t *testing.T) {
	tests := map[string]string{
		"":               "''",
		"simple":         "'simple'",
		"mkdir -p $HOME": "'mkdir -p $HOME'",
		"can't touch":    "'can'\"'\"'t touch'",
	}
	for input, want := range tests {
		if got := ShellQuote(input); got != want {
			t.Fatalf("ShellQuote(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestValidateRootDir(t *testing.T) {
	tests := []struct {
		dir   string
		kind  target.Kind
		valid bool
	}{
		{"~/.devdiag/remote/s1", target.KindSSH, true},
		{"/tmp/devdiag-remote/s1", target.KindContainer, true},
		{"/", target.KindSSH, false},
		{"/home", target.KindSSH, false},
		{"/tmp", target.KindContainer, false},
		{"/tmp/not-devdiag/s1", target.KindContainer, false},
		{"~/.devdiag/remote/s1';rm -rf /", target.KindSSH, false},
		{"/tmp/devdiag-remote/s1;rm -rf /", target.KindContainer, false},
		{"", target.KindSSH, false},
		{"~/foo/..", target.KindSSH, false},
		{"/tmp/devdiag-remote/s1", target.KindSSH, false}, // ssh must contain .devdiag/remote
	}
	for _, tt := range tests {
		t.Run(tt.dir, func(t *testing.T) {
			err := ValidateRootDir(tt.dir, tt.kind)
			if (err == nil) != tt.valid {
				t.Fatalf("ValidateRootDir(%q) error = %v, want valid=%v", tt.dir, err, tt.valid)
			}
		})
	}
}

func TestValidateManagedPath(t *testing.T) {
	tests := []struct {
		root string
		path string
		ok   bool
	}{
		{"~/.devdiag/remote/s1", "~/.devdiag/remote/s1/env.sh", true},
		{"~/.devdiag/remote/s1", "~/.devdiag/remote/s1/../env.sh", false},
		{"~/.devdiag/remote/s1", "/etc/passwd", false},
		{"/tmp/devdiag-remote/s1", "/tmp/devdiag-remote/s1/env.sh", true},
		{"/tmp/devdiag-remote/s1", "/tmp/other/env.sh", false},
		{"/tmp/devdiag-remote/s1", "/tmp/devdiag-remote/s10/env.sh", false},
		{"~/.devdiag/remote/s1", "~/.devdiag/remote/s10/env.sh", false},
		{"~/.devdiag/remote/s1", "~/.devdiag/remote/s1/evil'quote", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			err := ValidateManagedPath(tt.root, tt.path)
			if (err == nil) != tt.ok {
				t.Fatalf("ValidateManagedPath(%q, %q) error = %v, want ok=%v", tt.root, tt.path, err, tt.ok)
			}
		})
	}
}
