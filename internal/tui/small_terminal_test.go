package tui

import (
	"strings"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/app"
)

func TestModel_View_SmallTerminalGuard(t *testing.T) {
	m := NewScanModel(app.ScanOptions{}, nil)
	m.scanning = false

	tests := []struct {
		name          string
		width, height int
		wantSmall     bool
	}{
		{"zero", 0, 0, true},
		{"tiny", 1, 1, true},
		{"too narrow", 10, 20, true},
		{"too short", 80, 5, true},
		{"boundary width", 39, 20, true},
		{"boundary height", 80, 7, true},
		{"just enough", 40, 8, false},
		{"normal", 80, 24, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m.width = tt.width
			m.height = tt.height

			view := m.View()
			if view == "" {
				t.Fatal("View returned empty string")
			}

			isSmall := strings.Contains(view, "Terminal too small")
			if isSmall != tt.wantSmall {
				t.Errorf("at %dx%d: got tooSmall=%v, want %v", tt.width, tt.height, isSmall, tt.wantSmall)
			}
		})
	}
}
