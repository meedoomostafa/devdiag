package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/logging"
	"github.com/meedoomostafa/devdiag/internal/output"
	"github.com/meedoomostafa/devdiag/internal/redact"
)

var (
	flagFormat  string
	flagRedact  string
	flagDebug   bool
	flagNoColor bool
	flagColor   string
	flagProfile string
)

var rootCmd = &cobra.Command{
	Use:   "devdiag",
	Short: "Linux-first, evidence-driven diagnostic CLI for developers",
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Validate flags
		if err := validateFormat(flagFormat); err != nil {
			return err
		}
		if err := validateRedact(flagRedact); err != nil {
			return err
		}
		if err := validateColor(flagColor); err != nil {
			return err
		}
		return nil
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	rootCmd.PersistentFlags().StringVar(&flagFormat, "format", "human", "Output format: human, json, ndjson, markdown")
	rootCmd.PersistentFlags().StringVar(&flagRedact, "redact", "default", "Redaction level: default, strict, off")
	rootCmd.PersistentFlags().BoolVar(&flagDebug, "debug", false, "Enable debug/trace logs")
	rootCmd.PersistentFlags().BoolVar(&flagNoColor, "no-color", false, "Disable ANSI color")
	rootCmd.PersistentFlags().StringVar(&flagColor, "color", "auto", "Color mode: always, auto, never")
	rootCmd.PersistentFlags().StringVar(&flagProfile, "profile", "", "Profile mode: ai-ml")

}

// Execute runs the CLI and returns the exit code.
func Execute() int {
	if err := rootCmd.Execute(); err != nil {
		// Write error to stderr so it never contaminates JSON stdout
		fmt.Fprintf(os.Stderr, "devdiag: %v\n", err)
		var ec exitCodeError
		if errors.As(err, &ec) {
			return ec.Code()
		}
		return exitcode.InternalError.Int()
	}
	return exitcode.Success.Int()
}

func validateFormat(v string) error {
	switch v {
	case "human", "json", "ndjson", "markdown":
		return nil
	}
	return exitCodeError{code: exitcode.InvalidInput}
}

func validateRedact(v string) error {
	switch v {
	case "default", "strict", "off":
		return nil
	}
	return exitCodeError{code: exitcode.InvalidInput}
}

func validateColor(v string) error {
	switch v {
	case "always", "auto", "never":
		return nil
	}
	return exitCodeError{code: exitcode.InvalidInput}
}

// buildRedactEngine creates the redaction engine from flags.
func buildRedactEngine() *redact.Engine {
	return redact.NewEngine(redact.Level(flagRedact))
}

// buildColorMode resolves color mode from flags.
func buildColorMode() output.ColorMode {
	return output.ResolveColorMode(flagColor, flagNoColor)
}

// buildLogger creates a logger with redaction.
func buildLogger() *logging.Logger {
	level := logging.LevelInfo
	if flagDebug {
		level = logging.LevelDebug
	}
	return logging.New(level, buildRedactEngine())
}

// exitCodeError wraps an exit code for typed error handling.
type exitCodeError struct {
	code exitcode.Code
}

func (e exitCodeError) Error() string {
	return fmt.Sprintf("exit code %d", e.code)
}

func (e exitCodeError) Code() int {
	return e.code.Int()
}
