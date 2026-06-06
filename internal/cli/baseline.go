package cli

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/baseline"
	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

var (
	baselineCreateReason      string
	baselineCreateExpires     string
	baselineCreateCreatedBy   string
	baselineCreateForce       bool
	baselineCreateRunID       string
	baselineCreateMinSev      string
	baselineCreateFingerprint bool

	baselineAddReason      string
	baselineAddExpires     string
	baselineAddCreatedBy   string
	baselineAddFingerprint string

	baselineRemoveFingerprint string
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

		reason := strings.TrimSpace(baselineCreateReason)
		if reason == "" {
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
			Reason:         reason,
			CreatedAt:      now,
			CreatedBy:      resolveCreatedBy(),
			UseFingerprint: baselineCreateFingerprint,
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
			tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "FINDING ID\tMATCH\tSTATUS\tEXPIRES AT\tCREATED BY\tCREATED AT\tREASON")
			for _, entry := range b.Entries {
				status := "active"
				if entry.ExpiresAt != nil && entry.ExpiresAt.Before(now) {
					status = "expired"
				}
				matchMode := baselineMatchMode(entry.Fingerprint)
				expiresStr := "-"
				if entry.ExpiresAt != nil {
					expiresStr = formatBaselineTime(*entry.ExpiresAt)
				}
				createdStr := formatBaselineTime(entry.CreatedAt)
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					entry.ID,
					matchMode,
					status,
					expiresStr,
					entry.CreatedBy,
					createdStr,
					entry.Reason,
				)
			}
			tw.Flush()
		}
		return nil
	},
}

var baselineValidateCmd = &cobra.Command{
	Use:   "validate [path]",
	Short: "Validate the baseline file format and schema",
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
		_, err = loadExistingBaseline(baselinePath)
		if err != nil {
			logger.Error("baseline", err.Error())
			return exitCodeError{code: exitcode.InvalidInput, message: fmt.Sprintf("validate baseline: %v", err)}
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Baseline at %s is valid.\n", baselinePath)
		return nil
	},
}

var baselinePathCmd = &cobra.Command{
	Use:   "path [path]",
	Short: "Print the absolute path to the baseline file",
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
		fmt.Fprintln(cmd.OutOrStdout(), baselinePath)
		return nil
	},
}

var baselineStatusCmd = &cobra.Command{
	Use:   "status [path]",
	Short: "Show status and statistics of the baseline file",
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
		if _, err := os.Stat(baselinePath); err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintf(cmd.OutOrStdout(), "Baseline: Not Found (%s)\n", baselinePath)
				return nil
			}
			logger.Error("baseline", err.Error())
			return exitCodeError{code: exitcode.InternalError, message: err.Error()}
		}

		b, err := baseline.Load(baselinePath)
		if err != nil {
			logger.Error("baseline", err.Error())
			return exitCodeError{code: exitcode.InvalidInput, message: fmt.Sprintf("load baseline: %v", err)}
		}

		now := time.Now().UTC()
		active := baseline.ActiveEntries(b, now)
		expired := len(b.Entries) - len(active)

		w := cmd.OutOrStdout()
		fmt.Fprintf(w, "Baseline Path: %s\n", baselinePath)
		fmt.Fprintln(w, "Status: Valid")
		fmt.Fprintf(w, "Active Entries: %d\n", len(active))
		fmt.Fprintf(w, "Expired Entries: %d\n", expired)
		return nil
	},
}

func loadExistingBaseline(path string) (*baseline.Baseline, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("baseline not found: %s", path)
		}
		return nil, err
	}
	return baseline.Load(path)
}

func baselineMatchMode(fingerprint string) string {
	if strings.TrimSpace(fingerprint) != "" {
		return "fingerprint"
	}
	return "id"
}

var baselinePruneCmd = &cobra.Command{
	Use:   "prune [path]",
	Short: "Prune expired entries from the baseline file",
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
		b, err := loadExistingBaseline(baselinePath)
		if err != nil {
			logger.Error("baseline", err.Error())
			return exitCodeError{code: exitcode.InvalidInput, message: fmt.Sprintf("load baseline: %v", err)}
		}

		now := time.Now().UTC()
		pruned := b.Prune(now)

		if err := baseline.Save(baselinePath, b); err != nil {
			logger.Error("baseline", err.Error())
			return exitCodeError{code: exitcode.InternalError, message: fmt.Sprintf("save baseline: %v", err)}
		}

		fmt.Fprintf(cmd.OutOrStdout(), "Pruned %d expired entries. %d active entries remaining.\n", pruned, len(b.Entries))
		return nil
	},
}

var baselineAddCmd = &cobra.Command{
	Use:   "add <finding-id> [path]",
	Short: "Manually add or update a baseline suppression entry",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := buildLogger()

		id := strings.ToUpper(strings.TrimSpace(args[0]))
		if id == "" {
			return exitCodeError{code: exitcode.InvalidInput, message: "finding ID cannot be empty"}
		}

		reason := strings.TrimSpace(baselineAddReason)
		if reason == "" {
			return exitCodeError{code: exitcode.InvalidInput, message: "--reason is required"}
		}

		fp := strings.TrimSpace(baselineAddFingerprint)
		if fp != "" && !baseline.IsValidFingerprint(fp) {
			return exitCodeError{code: exitcode.InvalidInput, message: fmt.Sprintf("invalid --fingerprint: %q (must be a 64-character lowercase hex SHA-256 hash)", fp)}
		}

		scanPath := "."
		if len(args) == 2 {
			scanPath = args[1]
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
		entry := baseline.Entry{
			ID:          id,
			Reason:      reason,
			CreatedAt:   now,
			Fingerprint: fp,
		}

		createdBy := strings.TrimSpace(baselineAddCreatedBy)
		if createdBy == "" {
			createdBy = strings.TrimSpace(resolveCreatedBy())
		}
		if createdBy == "" {
			createdBy = "unknown"
		}
		entry.CreatedBy = createdBy

		if baselineAddExpires != "" {
			expiresAt, err := baseline.ParseExpiryDuration(baselineAddExpires, now)
			if err != nil {
				return exitCodeError{code: exitcode.InvalidInput, message: err.Error()}
			}
			entry.ExpiresAt = &expiresAt
		}

		updated, err := b.Add(entry)
		if err != nil {
			return exitCodeError{code: exitcode.InvalidInput, message: err.Error()}
		}

		if err := baseline.Save(baselinePath, b); err != nil {
			logger.Error("baseline", err.Error())
			return exitCodeError{code: exitcode.InternalError, message: fmt.Sprintf("save baseline: %v", err)}
		}

		mode := baselineMatchMode(fp)
		if updated {
			fmt.Fprintf(cmd.OutOrStdout(), "Updated entry for %s (match: %s) in baseline.\n", id, mode)
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "Added entry for %s (match: %s) to baseline.\n", id, mode)
		}
		return nil
	},
}

var baselineRemoveCmd = &cobra.Command{
	Use:   "remove <finding-id> [path]",
	Short: "Manually remove a baseline suppression entry",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := buildLogger()

		id := strings.ToUpper(strings.TrimSpace(args[0]))
		if id == "" {
			return exitCodeError{code: exitcode.InvalidInput, message: "finding ID cannot be empty"}
		}

		fp := strings.TrimSpace(baselineRemoveFingerprint)
		if fp != "" && !baseline.IsValidFingerprint(fp) {
			return exitCodeError{code: exitcode.InvalidInput, message: fmt.Sprintf("invalid --fingerprint: %q (must be a 64-character lowercase hex SHA-256 hash)", fp)}
		}

		scanPath := "."
		if len(args) == 2 {
			scanPath = args[1]
		}
		absPath, err := resolveExistingDirectory(scanPath)
		if err != nil {
			logger.Error("baseline", err.Error())
			return exitCodeError{code: exitcode.InvalidInput, message: err.Error()}
		}

		baselinePath := baseline.DefaultPath(absPath)
		b, err := loadExistingBaseline(baselinePath)
		if err != nil {
			logger.Error("baseline", err.Error())
			return exitCodeError{code: exitcode.InvalidInput, message: fmt.Sprintf("load baseline: %v", err)}
		}

		removed := b.Remove(id, fp)
		if !removed {
			mode := baselineMatchMode(fp)
			return exitCodeError{
				code:    exitcode.InvalidInput,
				message: fmt.Sprintf("baseline entry not found: %s (match: %s)", id, mode),
			}
		}

		if err := baseline.Save(baselinePath, b); err != nil {
			logger.Error("baseline", err.Error())
			return exitCodeError{code: exitcode.InternalError, message: fmt.Sprintf("save baseline: %v", err)}
		}

		mode := baselineMatchMode(fp)
		fmt.Fprintf(cmd.OutOrStdout(), "Removed entry for %s (match: %s) from baseline.\n", id, mode)
		return nil
	},
}

const baselineTimeFormat = "2006-01-02 15:04:05"

func formatBaselineTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(baselineTimeFormat)
}

// resolveCreatedBy determines the author of the baseline entry.
func resolveCreatedBy() string {
	if baselineCreateCreatedBy != "" {
		return strings.TrimSpace(baselineCreateCreatedBy)
	}
	if user := os.Getenv("USER"); user != "" {
		return strings.TrimSpace(user)
	}
	if user := os.Getenv("USERNAME"); user != "" {
		return strings.TrimSpace(user)
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
	baselineCreateCmd.Flags().BoolVar(&baselineCreateFingerprint, "fingerprint", false, "Create baseline entries with exact finding fingerprints (opt-in)")

	baselineAddCmd.Flags().StringVar(&baselineAddReason, "reason", "", "Reason for accepting this finding (required)")
	baselineAddCmd.Flags().StringVar(&baselineAddExpires, "expires", "", "Expiry duration (e.g., 30d, 12h, 90m)")
	baselineAddCmd.Flags().StringVar(&baselineAddCreatedBy, "created-by", "", "Author of the baseline entry (default: $USER)")
	baselineAddCmd.Flags().StringVar(&baselineAddFingerprint, "fingerprint", "", "Exact finding fingerprint (optional)")

	baselineRemoveCmd.Flags().StringVar(&baselineRemoveFingerprint, "fingerprint", "", "Exact finding fingerprint (optional)")

	baselineCmd.AddCommand(baselineCreateCmd)
	baselineCmd.AddCommand(baselineListCmd)
	baselineCmd.AddCommand(baselineValidateCmd)
	baselineCmd.AddCommand(baselinePathCmd)
	baselineCmd.AddCommand(baselineStatusCmd)
	baselineCmd.AddCommand(baselinePruneCmd)
	baselineCmd.AddCommand(baselineAddCmd)
	baselineCmd.AddCommand(baselineRemoveCmd)
	rootCmd.AddCommand(baselineCmd)
}
