package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

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
	case "github":
		return &output.GitHubRenderer{}
	default:
		return &output.HumanRenderer{ColorMode: colorMode, Verbose: flagVerbose}
	}
}

func severityHigher(a, b schema.Severity) bool {
	return severityRank(a) > severityRank(b)
}

func severityRank(severity schema.Severity) int {
	order := map[schema.Severity]int{
		schema.SeverityCritical: 4,
		schema.SeverityHigh:     3,
		schema.SeverityMedium:   2,
		schema.SeverityLow:      1,
		schema.SeverityInfo:     0,
	}
	return order[severity]
}

// exitCodeFromResults computes the CLI exit code honoring the contract:
//
//	0 = success, 1 = findings exist, 2 = invalid input,
//	3 = collector partial failure, 4 = permission denied,
//	5 = unsafe refused, 6 = repro failed, 7 = trace unavailable, 8 = internal error.
func exitCodeFromResults(findings []schema.Finding, collectors []schema.CollectorResult, reproFailed bool) exitcode.Code {
	return exitCodeFromResultsWithThreshold(findings, collectors, reproFailed, flagFailSeverity)
}

func exitCodeFromResultsForCommand(cmd *cobra.Command, findings []schema.Finding, collectors []schema.CollectorResult, reproFailed bool) exitcode.Code {
	return exitCodeFromResultsWithThreshold(findings, collectors, reproFailed, effectiveFailSeverity(cmd, collectors))
}

func effectiveFailSeverity(cmd *cobra.Command, collectors []schema.CollectorResult) string {
	if failSeverityFlagChanged(cmd) {
		return flagFailSeverity
	}
	if configured, ok := configuredFailSeverity(collectors); ok {
		return configured
	}
	return flagFailSeverity
}

func failSeverityFlagChanged(cmd *cobra.Command) bool {
	if cmd == nil {
		return false
	}
	for current := cmd; current != nil; current = current.Parent() {
		for _, flags := range []*pflag.FlagSet{current.Flags(), current.PersistentFlags(), current.InheritedFlags()} {
			if flag := flags.Lookup("fail-severity"); flag != nil && flag.Changed {
				return true
			}
		}
	}
	return false
}

func configuredFailSeverity(collectors []schema.CollectorResult) (string, bool) {
	for _, collector := range collectors {
		if collector.Name != "config" {
			continue
		}
		for _, evidence := range collector.Evidence {
			if evidence.Source != "devdiag_policy_fail_severity" {
				continue
			}
			value := strings.TrimSpace(evidence.Value)
			if _, _, ok := parseFailSeverityThreshold(value); ok {
				return value, true
			}
		}
	}
	return "", false
}

func exitCodeFromResultsWithThreshold(findings []schema.Finding, collectors []schema.CollectorResult, reproFailed bool, thresholdValue string) exitcode.Code {
	maxSeverity := schema.SeverityInfo
	for _, f := range findings {
		if severityHigher(f.Severity, maxSeverity) {
			maxSeverity = f.Severity
		}
	}

	if reproFailed {
		return exitcode.ReproFailed
	}
	threshold, disabled, ok := parseFailSeverityThreshold(thresholdValue)
	if !ok {
		threshold = schema.SeverityHigh
	}
	if !disabled && severityRank(maxSeverity) >= severityRank(threshold) {
		return exitcode.FindingsExist
	}

	for _, c := range collectors {
		switch c.Status {
		case schema.CollectorPartial:
			return exitcode.CollectorPartial
		case schema.CollectorTimeout:
			return exitcode.CollectorPartial
		case schema.CollectorPermissionDenied:
			return exitcode.PermissionDenied
		case schema.CollectorFailed:
			return exitcode.CollectorPartial
		}
	}
	return exitcode.Success
}

func parseFailSeverityThreshold(v string) (schema.Severity, bool, bool) {
	switch v {
	case "off":
		return schema.SeverityCritical, true, true
	case "info":
		return schema.SeverityInfo, false, true
	case "low":
		return schema.SeverityLow, false, true
	case "medium":
		return schema.SeverityMedium, false, true
	case "high":
		return schema.SeverityHigh, false, true
	case "critical":
		return schema.SeverityCritical, false, true
	default:
		return schema.SeverityHigh, false, false
	}
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
