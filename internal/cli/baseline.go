package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/baseline"
	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

var (
	baselineCreateReason    string
	baselineCreateExpires   string
	baselineCreateCreatedBy string
	baselineCreateForce     bool
	baselineCreateRunID     string
	baselineCreateMinSev    string
)

var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Manage accepted-findings baseline",
}

var baselineCreateCmd = &cobra.Command{
	Use:   "create [path]",
	Short: "Create a baseline file from a saved scan report",
	Long: `Create a .devdiag/baseline.yaml file from the latest saved scan report.
All visible findings from the saved report become baseline entries.

If the saved report was created without --include-hidden, low/info/evidence-only
findings are not present and cannot be baselined from that report.`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := buildLogger()

		if baselineCreateReason == "" {
			return exitCodeError{code: exitcode.InvalidInput, message: "--reason is required"}
		}

		scanPath := "."
		if len(args) > 0 {
			scanPath = args[0]
		}
		absPath, err := resolveExistingDirectory(scanPath)
		if err != nil {
			logger.Error("baseline", err.Error())
			return exitCodeError{code: exitcode.InvalidInput, message: err.Error()}
		}

		// Load the saved report.
		var rep *schema.Report
		if baselineCreateRunID != "" {
			rep, err = resolveReportFromRunID(absPath, baselineCreateRunID)
		} else {
			rep, _, err = resolveLatestReport(absPath)
		}
		if err != nil {
			logger.Error("baseline", err.Error())
			return exitCodeError{code: exitcode.InvalidInput, message: fmt.Sprintf("load saved report: %v", err)}
		}

		// Check if baseline already exists.
		baselinePath := baseline.DefaultPath(absPath)
		if !baselineCreateForce {
			if _, err := os.Stat(baselinePath); err == nil {
				return exitCodeError{
					code:    exitcode.InvalidInput,
					message: fmt.Sprintf("baseline already exists at %s; use --force to overwrite", baselinePath),
				}
			}
		}

		// Build create options.
		now := time.Now().UTC()
		opts := baseline.CreateOptions{
			Reason:    baselineCreateReason,
			CreatedAt: now,
			CreatedBy: resolveCreatedBy(),
		}

		// Parse expiry.
		if baselineCreateExpires != "" {
			expiresAt, err := baseline.ParseExpiryDuration(baselineCreateExpires, now)
			if err != nil {
				return exitCodeError{code: exitcode.InvalidInput, message: err.Error()}
			}
			opts.ExpiresAt = &expiresAt
		}

		// Parse min severity.
		if baselineCreateMinSev != "" {
			sev, ok := parseSeverity(baselineCreateMinSev)
			if !ok {
				return exitCodeError{
					code:    exitcode.InvalidInput,
					message: fmt.Sprintf("invalid --min-severity: %s (allowed: info, low, medium, high, critical)", baselineCreateMinSev),
				}
			}
			opts.MinSeverity = sev
		}

		b := baseline.CreateFromFindings(rep.Findings, opts)
		if err := baseline.Save(baselinePath, b); err != nil {
			logger.Error("baseline", err.Error())
			return exitCodeError{code: exitcode.InternalError, message: fmt.Sprintf("save baseline: %v", err)}
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Created baseline with %d entries at %s\n", len(b.Entries), baselinePath)
		return nil
	},
}

var baselineListCmd = &cobra.Command{
	Use:   "list [path]",
	Short: "List entries in the current baseline file",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := buildLogger()

		scanPath := "."
		if len(args) > 0 {
			scanPath = args[0]
		}
		absPath, err := resolveExistingDirectory(scanPath)
		if err != nil {
			logger.Error("baseline", err.Error())
			return exitCodeError{code: exitcode.InvalidInput, message: err.Error()}
		}

		baselinePath := baseline.DefaultPath(absPath)
		b, err := baseline.Load(baselinePath)
		if err != nil {
			logger.Error("baseline", err.Error())
			return exitCodeError{code: exitcode.InvalidInput, message: fmt.Sprintf("load baseline: %v", err)}
		}

		now := time.Now().UTC()
		active := baseline.ActiveEntries(b, now)
		expired := len(b.Entries) - len(active)

		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "Baseline: %s\n", baselinePath)
		fmt.Fprintf(w, "Total: %d entries (%d active, %d expired)\n", len(b.Entries), len(active), expired)
		if len(b.Entries) > 0 {
			fmt.Fprintln(w)
			for _, entry := range b.Entries {
				status := "active"
				if entry.ExpiresAt != nil && entry.ExpiresAt.Before(now) {
					status = "expired"
				}
				fmt.Fprintf(w, "  %-25s [%s]", entry.ID, status)
				if entry.Reason != "" {
					fmt.Fprintf(w, "  %s", entry.Reason)
				}
				fmt.Fprintln(w)
			}
		}
		return nil
	},
}

// resolveCreatedBy determines the author of the baseline entry.
func resolveCreatedBy() string {
	if baselineCreateCreatedBy != "" {
		return baselineCreateCreatedBy
	}
	if user := os.Getenv("USER"); user != "" {
		return user
	}
	if user := os.Getenv("USERNAME"); user != "" {
		return user
	}
	return "unknown"
}

func parseSeverity(v string) (schema.Severity, bool) {
	switch v {
	case "info":
		return schema.SeverityInfo, true
	case "low":
		return schema.SeverityLow, true
	case "medium":
		return schema.SeverityMedium, true
	case "high":
		return schema.SeverityHigh, true
	case "critical":
		return schema.SeverityCritical, true
	default:
		return "", false
	}
}

func init() {
	baselineCreateCmd.Flags().StringVar(&baselineCreateReason, "reason", "", "Reason for accepting these findings (required)")
	baselineCreateCmd.Flags().StringVar(&baselineCreateExpires, "expires", "", "Expiry duration for all entries (e.g., 30d, 12h, 90m)")
	baselineCreateCmd.Flags().StringVar(&baselineCreateCreatedBy, "created-by", "", "Author of the baseline entries (default: $USER)")
	baselineCreateCmd.Flags().BoolVar(&baselineCreateForce, "force", false, "Overwrite existing baseline file")
	baselineCreateCmd.Flags().StringVar(&baselineCreateRunID, "run-id", "", "Use a specific saved run instead of latest")
	baselineCreateCmd.Flags().StringVar(&baselineCreateMinSev, "min-severity", "", "Minimum finding severity to include (info, low, medium, high, critical)")

	baselineCmd.AddCommand(baselineCreateCmd)
	baselineCmd.AddCommand(baselineListCmd)
	rootCmd.AddCommand(baselineCmd)
}
