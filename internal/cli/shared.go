package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/output"
	"github.com/meedoomostafa/devdiag/internal/schema"
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

// exitCodeFromResults computes the CLI exit code honoring the contract:
//
//	0 = success, 1 = findings exist, 2 = invalid input,
//	3 = collector partial failure, 4 = permission denied,
//	5 = unsafe refused, 6 = repro failed, 7 = trace unavailable, 8 = internal error.
func exitCodeFromResults(findings []schema.Finding, collectors []schema.CollectorResult, reproFailed bool) exitcode.Code {
	maxSeverity := schema.SeverityInfo
	for _, f := range findings {
		if severityHigher(f.Severity, maxSeverity) {
			maxSeverity = f.Severity
		}
	}

	if reproFailed {
		return exitcode.ReproFailed
	}
	if maxSeverity == schema.SeverityHigh || maxSeverity == schema.SeverityCritical {
		return exitcode.FindingsExist
	}

	for _, c := range collectors {
		switch c.Status {
		case schema.CollectorTimeout:
			return exitcode.CollectorPartial
		case schema.CollectorPermissionDenied:
			return exitcode.PermissionDenied
		case schema.CollectorUnavailable:
			return exitcode.CollectorPartial
		case schema.CollectorFailed:
			return exitcode.CollectorPartial
		}
	}
	return exitcode.Success
}

// exitCodeFromFixResults computes the CLI exit code for fix commands:
//
//	0 = proposals rendered / dry-run / apply success
//	2 = invalid input
//	3 = report/evidence unavailable
//	4 = permission denied during apply
//	5 = unsafe operation refused
//	8 = internal error.
func exitCodeFromFixResults(reportFound bool, blocked bool, internalErr bool) exitcode.Code {
	if internalErr {
		return exitcode.InternalError
	}
	if blocked {
		return exitcode.UnsafeRefused
	}
	if !reportFound {
		return exitcode.CollectorPartial
	}
	return exitcode.Success
}

// populateHostInfo extracts host metadata from the host collector evidence.
func populateHostInfo(collectors []schema.CollectorResult) schema.HostInfo {
	var host schema.HostInfo
	for _, c := range collectors {
		if c.Name != "host" {
			continue
		}
		for _, ev := range c.Evidence {
			switch ev.Source {
			case "host_os_id":
				host.OS = ev.Value
			case "host_os_version":
				host.Version = ev.Value
			case "host_kernel":
				host.Kernel = ev.Value
			case "host_arch":
				host.Arch = ev.Value
			}
		}
	}
	return host
}
