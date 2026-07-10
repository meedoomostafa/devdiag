// Package cueerr converts CUE validation errors into flat string slices for
// user-facing schema validation results.
package cueerr

import (
	"strings"

	cueerrors "cuelang.org/go/cue/errors"
)

// Split flattens a CUE error into trimmed, non-empty detail lines.
// It always returns at least one line for a non-nil error.
func Split(err error) []string {
	if err == nil {
		return nil
	}
	var out []string
	details := cueerrors.Details(err, nil)
	if strings.TrimSpace(details) == "" {
		details = err.Error()
	}
	for _, line := range strings.Split(details, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		out = append(out, err.Error())
	}
	return out
}
