package output

import (
	"os"

	"golang.org/x/term"
)

// ColorMode controls whether ANSI color sequences are emitted.
type ColorMode string

const (
	ColorAlways ColorMode = "always"
	ColorAuto   ColorMode = "auto"
	ColorNever  ColorMode = "never"
)

// ResolveColorMode determines the effective color mode.
// Precedence: NO_COLOR env wins over --color unless --color always is explicitly set.
// --no-color is treated as --color never.
func ResolveColorMode(flagColor string, flagNoColor bool) ColorMode {
	// --no-color forces never
	if flagNoColor {
		return ColorNever
	}

	// If --color always is explicitly set, it wins over NO_COLOR
	if flagColor == string(ColorAlways) {
		return ColorAlways
	}

	// NO_COLOR forces never
	if os.Getenv("NO_COLOR") != "" {
		return ColorNever
	}

	// Otherwise respect --color flag (auto/never) or default to auto
	if flagColor == string(ColorNever) {
		return ColorNever
	}
	return ColorAuto
}

// IsTTY returns whether the given file descriptor is an interactive terminal.
func IsTTY(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}

// ShouldColor returns true if color should be emitted.
func ShouldColor(mode ColorMode, isTTY bool) bool {
	switch mode {
	case ColorAlways:
		return true
	case ColorNever:
		return false
	default:
		return isTTY
	}
}
