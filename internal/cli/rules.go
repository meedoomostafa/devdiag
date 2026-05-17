package cli

import (
	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/schema"
	"github.com/meedoomostafa/devdiag/internal/version"
)

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "List available diagnostic rules",
}

var rulesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available diagnostic rules",
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := buildLogger()
		colorMode := buildColorMode()
		redactEngine := buildRedactEngine()

		if flagRedact == "off" {
			logger.Warn("redact", "redaction is disabled; secrets may be visible")
		}

		switch flagFormat {
		case "json", "ndjson", "markdown":
			report := &schema.Report{
				SchemaVersion:   schema.SchemaVersion,
				DevDiagVersion:  version.Version,
				RunID:           generateRunID(),
				RedactionStatus: string(redactEngine.Level),
				Repo:            schema.RepoInfo{},
				Host:            schema.HostInfo{},
				Collectors:      []schema.CollectorResult{},
				Findings:        availableRuleFindings(),
			}
			renderer := pickRenderer(colorMode)
			redacted := redactEngine.RedactReport(report)
			return renderer.Render(redacted, cmd.OutOrStdout())
		default:
			// human mode — route through renderer for consistency
			report := &schema.Report{
				SchemaVersion:   schema.SchemaVersion,
				DevDiagVersion:  version.Version,
				RunID:           generateRunID(),
				RedactionStatus: string(redactEngine.Level),
				Repo:            schema.RepoInfo{},
				Host:            schema.HostInfo{},
				Collectors:      []schema.CollectorResult{},
				Findings:        availableRuleFindings(),
			}
			renderer := pickRenderer(colorMode)
			redacted := redactEngine.RedactReport(report)
			return renderer.Render(redacted, cmd.OutOrStdout())
		}
	},
}

func availableRuleFindings() []schema.Finding {
	rules := []struct {
		id    string
		title string
	}{
		{"F-ENV-001", "Missing required env var"},
		{"F-ENV-002", "Compose references undefined env var"},
		{"F-GIT-001", "Env file tracked by Git"},
		{"F-GIT-002", "Env file is not ignored"},
		{"F-PM-001", "Multiple package managers detected"},
		{"F-RUNTIME-001", "Node version mismatch"},
		{"F-RUNTIME-002", "Python version mismatch"},
		{"F-RUNTIME-003", "Required runtime missing"},
		{"F-RUNTIME-004", ".NET SDK version mismatch"},
		{"F-RUNTIME-005", "Go version mismatch"},
		{"F-RUNTIME-006", "Rust version mismatch"},
		{"F-RUNTIME-DECL-001", "Runtime version declaration discovered"},
		{"F-DISK-001", "Disk or inode exhaustion"},
		{"F-PORT-001", "Host port collision"},
		{"F-NET-001", "Proxy env var set but NO_PROXY is empty"},
		{"F-SVC-001", "Required service inactive"},
		{"F-FS-001", "Script missing executable bit"},
		{"F-PERM-002", "Root-owned workspace artifact"},
		{"F-DOCKER-001", "Docker daemon inactive or inaccessible"},
		{"F-DOCKER-002", "Docker socket permission denied"},
		{"F-DOCKER-003", "Docker Compose plugin missing"},
		{"F-PODMAN-001", "Podman unavailable"},
		{"F-CONTAINER-001", "Compose service unhealthy"},
		{"F-CONTAINER-003", "Compose service exited"},
		{"F-REPRO-001", "Reproduced command failure"},
		{"F-REPRO-009", "Command timed out"},
		{"F-GPU-001", "NVIDIA hardware present but driver unavailable"},
		{"F-GPU-002", "Secure Boot may block NVIDIA module"},
		{"F-ML-PYTORCH-001", "PyTorch CPU-only build with GPU present"},
		{"F-ML-PYTORCH-002", "PyTorch CUDA build sees no GPU"},
		{"F-ML-TF-001", "TensorFlow installed but no GPU visible"},
		{"F-ML-JAX-001", "JAX installed but no GPU visible"},
		{"F-DOCKER-GPU-001", "Docker GPU runtime unavailable"},
		{"F-DOCKER-GPU-002", "Container GPU verification failed"},
		{"F-CACHE-001", "Package cache not writable"},
		{"F-CACHE-002", "Package cache appears root-owned"},
		{"F-CACHE-003", "Docker cache unusually large"},
		{"F-CI-PACKAGE-001", "CI package manager differs from local"},
		{"F-CI-PACKAGE-002", "CI command package manager differs from local"},
		{"F-CI-COMMAND-001", "CI command missing locally"},
		{"F-CI-RUNTIME-001", "CI runtime version differs from local"},
		{"F-CI-ENV-001", "CI env var missing locally"},
		{"F-CI-ENV-002", "Local env var missing in CI"},
		{"F-CI-SERVICE-001", "CI service missing locally"},
		{"F-CI-SERVICE-002", "Local service missing in CI"},
		{"F-CI-CONTAINER-001", "CI container differs from devcontainer"},
		{"F-CI-SHELL-001", "CI shell differs from local"},
		{"F-TRACE-FILE-001", "Trace detected missing file access"},
		{"F-TRACE-FILE-002", "Trace detected permission-denied file access"},
		{"F-TRACE-NET-001", "Trace detected refused network connection"},
	}

	findings := make([]schema.Finding, 0, len(rules))
	for _, r := range rules {
		findings = append(findings, schema.Finding{
			ID:              r.id,
			Title:           r.title,
			Severity:        schema.SeverityInfo,
			Confidence:      1,
			Symptom:         "Implemented diagnostic rule available",
			RedactionStatus: "safe",
		})
	}
	return findings
}

func init() {
	rulesCmd.AddCommand(rulesListCmd)
	rootCmd.AddCommand(rulesCmd)
}
