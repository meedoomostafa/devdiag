package output

import (
	"testing"
)

func TestResolveColorMode_NoColorFlag(t *testing.T) {
	// --no-color should force never
	mode := ResolveColorMode("auto", true)
	if mode != ColorNever {
		t.Errorf("ResolveColorMode(auto, noColor=true) = %v, want never", mode)
	}
}

func TestResolveColorMode_ColorAlwaysWinsOverAuto(t *testing.T) {
	mode := ResolveColorMode("always", false)
	if mode != ColorAlways {
		t.Errorf("ResolveColorMode(always) = %v, want always", mode)
	}
}

func TestResolveColorMode_DefaultIsAuto(t *testing.T) {
	t.Setenv("NO_COLOR", "")

	mode := ResolveColorMode("auto", false)
	if mode != ColorAuto {
		t.Errorf("ResolveColorMode(auto) = %v, want auto", mode)
	}
}

func TestResolveColorMode_NoColorEnv(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	mode := ResolveColorMode("auto", false)
	if mode != ColorNever {
		t.Errorf("ResolveColorMode(auto) with NO_COLOR = %v, want never", mode)
	}
}

func TestShouldColor(t *testing.T) {
	if !ShouldColor(ColorAlways, false) {
		t.Error("ShouldColor(always, nonTTY) should be true")
	}
	if ShouldColor(ColorNever, true) {
		t.Error("ShouldColor(never, TTY) should be false")
	}
	if !ShouldColor(ColorAuto, true) {
		t.Error("ShouldColor(auto, TTY) should be true")
	}
	if ShouldColor(ColorAuto, false) {
		t.Error("ShouldColor(auto, nonTTY) should be false")
	}
}
