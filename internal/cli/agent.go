package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/agent"
	"github.com/meedoomostafa/devdiag/internal/exitcode"
)

var (
	agentRunTimeout     time.Duration
	agentSandboxTimeout time.Duration
	agentPatch          string
	agentKeep           bool
)

var agentCmd = &cobra.Command{
	Use:   "agent",
	Short: "Deterministic agent-safe explanation, command, and sandbox tools",
}

var agentExplainCmd = &cobra.Command{
	Use:   "explain <finding-id-or-path>",
	Short: "Build an agent-safe explanation context from a finding id or file",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		redactor := buildRedactEngine()
		root, _ := os.Getwd()
		input := agent.Input{Kind: "repo_text", Path: args[0], Content: args[0]}
		if data, err := os.ReadFile(args[0]); err == nil {
			input.Content = string(data)
		} else {
			input.Kind = "finding_ref"
		}
		ctx := agent.BuildContext(agent.ContextRequest{
			Root: root,
			Inputs: []agent.Input{
				input,
			},
			Redact: func(s string) string { return redactor.RedactString(s, "agent_context") },
		})
		return renderAgentValue(cmd, ctx)
	},
}

var agentRunCmd = &cobra.Command{
	Use:   "run -- <cmd> [args...]",
	Short: "Run a command and report redacted, agent-safe evidence",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		redactor := buildRedactEngine()
		root, _ := os.Getwd()
		result := agent.RunCommand(cmd.Context(), agent.RunRequest{
			Command:     args[0],
			Args:        args[1:],
			Dir:         root,
			Timeout:     agentRunTimeout,
			Redact:      func(s string) string { return redactor.RedactString(s, "agent_run") },
			RedactLevel: string(redactor.Level),
		})
		if err := renderAgentValue(cmd, result); err != nil {
			return err
		}
		if result.ExitCode != 0 || result.TimedOut {
			return exitCodeError{code: exitcode.ReproFailed}
		}
		return nil
	},
}

var agentSandboxCmd = &cobra.Command{
	Use:   "sandbox --patch <patch> -- <cmd> [args...]",
	Short: "Apply a patch in an isolated temporary copy and run a command",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if agentPatch == "" {
			return exitCodeError{code: exitcode.InvalidInput}
		}
		root, err := os.Getwd()
		if err != nil {
			return err
		}
		patchPath, err := filepath.Abs(agentPatch)
		if err != nil {
			return exitCodeError{code: exitcode.InvalidInput}
		}
		redactor := buildRedactEngine()
		result, err := agent.RunSandbox(cmd.Context(), agent.SandboxRequest{
			Root:        root,
			PatchPath:   patchPath,
			Keep:        agentKeep,
			Redact:      func(s string) string { return redactor.RedactString(s, "agent_sandbox") },
			RedactLevel: string(redactor.Level),
			Run: agent.RunRequest{
				Command: args[0],
				Args:    args[1:],
				Timeout: agentSandboxTimeout,
			},
		})
		if err != nil {
			return err
		}
		if err := renderAgentValue(cmd, result); err != nil {
			return err
		}
		if !result.PatchApplied || result.Run == nil || result.Run.ExitCode != 0 || result.Run.TimedOut {
			return exitCodeError{code: exitcode.ReproFailed}
		}
		return nil
	},
}

func init() {
	agentRunCmd.Flags().DurationVar(&agentRunTimeout, "timeout", 30*time.Second, "Command timeout")
	agentSandboxCmd.Flags().DurationVar(&agentSandboxTimeout, "timeout", 30*time.Second, "Sandbox command timeout")
	agentSandboxCmd.Flags().StringVar(&agentPatch, "patch", "", "Patch file to apply inside the sandbox")
	agentSandboxCmd.Flags().BoolVar(&agentKeep, "keep", false, "Keep the sandbox directory after execution")
	agentCmd.AddCommand(agentExplainCmd)
	agentCmd.AddCommand(agentRunCmd)
	agentCmd.AddCommand(agentSandboxCmd)
	rootCmd.AddCommand(agentCmd)
}

func renderAgentValue(cmd *cobra.Command, value any) error {
	switch flagFormat {
	case "json":
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(value)
	case "ndjson":
		return json.NewEncoder(cmd.OutOrStdout()).Encode(value)
	default:
		return renderAgentHuman(cmd, value)
	}
}

func renderAgentHuman(cmd *cobra.Command, value any) error {
	var b strings.Builder
	switch v := value.(type) {
	case agent.Context:
		b.WriteString("DevDiag agent context\n")
		b.WriteString(fmt.Sprintf("Inputs: %d\n", len(v.Inputs)))
		b.WriteString(fmt.Sprintf("Findings: %d\n", len(v.Findings)))
	case agent.RunResult:
		b.WriteString("DevDiag agent run\n")
		b.WriteString(fmt.Sprintf("Command: %s\n", v.Command))
		b.WriteString(fmt.Sprintf("Exit code: %d\n", v.ExitCode))
		b.WriteString(fmt.Sprintf("Findings: %d\n", len(v.Findings)))
	case agent.SandboxResult:
		b.WriteString("DevDiag agent sandbox\n")
		b.WriteString(fmt.Sprintf("Patch applied: %t\n", v.PatchApplied))
		b.WriteString(fmt.Sprintf("Cleanup: %s\n", v.CleanupStatus))
		if v.Run != nil {
			b.WriteString(fmt.Sprintf("Run exit code: %d\n", v.Run.ExitCode))
		}
	default:
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return err
		}
		b.Write(data)
		b.WriteString("\n")
	}
	_, err := cmd.OutOrStdout().Write([]byte(b.String()))
	return err
}
