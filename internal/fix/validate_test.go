package fix

import (
	"testing"
)

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name    string
		root    string
		value   string
		wantErr bool
	}{
		{"empty", "", "", true},
		{"simple relative", "/repo", "script.sh", false},
		{"with traversal", "/repo", "../etc/passwd", true},
		{"safe absolute", "", "/tmp/test.sh", false},
		{"bad absolute", "", "/etc/passwd", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidatePath(tt.root, tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidatePath(%q, %q) error = %v, wantErr %v", tt.root, tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePort(t *testing.T) {
	tests := []struct {
		value   string
		want    int
		wantErr bool
	}{
		{"80", 80, false},
		{"0", 0, true},
		{"65535", 65535, false},
		{"65536", 0, true},
		{"abc", 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			got, err := ValidatePort(tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidatePort(%q) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("ValidatePort(%q) = %d, want %d", tt.value, got, tt.want)
			}
		})
	}
}

func TestValidateServiceName(t *testing.T) {
	tests := []struct {
		value   string
		wantErr bool
	}{
		{"app", false},
		{"app-db", false},
		{"", true},
		{"app;rm", true},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			_, err := ValidateServiceName(tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateServiceName(%q) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestValidateEnvKey(t *testing.T) {
	tests := []struct {
		value   string
		wantErr bool
	}{
		{"DATABASE_URL", false},
		{"123_BAD", true},
		{"", true},
		{"A=B", true},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			_, err := ValidateEnvKey(tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateEnvKey(%q) error = %v, wantErr %v", tt.value, err, tt.wantErr)
			}
		})
	}
}
