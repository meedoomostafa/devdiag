package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/meedoomostafa/devdiag/internal/output"
)

// generateRunID creates a simple run identifier using a single timestamp
// and a crypto/rand hex suffix for uniqueness.
func generateRunID() string {
	ts := time.Now().UTC()
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		// Fallback to nanosecond portion on crypto/rand failure
		return fmt.Sprintf("%s_%04x", ts.Format("2006-01-02T15:04:05Z"), ts.UnixNano()%0xFFFF)
	}
	return fmt.Sprintf("%s_%s", ts.Format("2006-01-02T15:04:05Z"), hex.EncodeToString(suffix))
}

// pickRenderer selects the appropriate renderer based on format and color mode.
func pickRenderer(colorMode output.ColorMode) output.Renderer {
	switch flagFormat {
	case "json":
		return &output.JSONRenderer{}
	case "ndjson":
		return &output.NDJSONRenderer{}
	case "markdown":
		return &output.MarkdownRenderer{}
	default:
		return &output.HumanRenderer{ColorMode: colorMode}
	}
}
