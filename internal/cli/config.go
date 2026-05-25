package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/configschema"
	"github.com/meedoomostafa/devdiag/internal/exitcode"
)

type configValidationOutput struct {
	configschema.Result
	Path string `json:"path"`
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Validate DevDiag project configuration",
}

var configValidateCmd = &cobra.Command{
	Use:   "validate [path]",
	Short: "Validate devdiag.yaml with the versioned CUE schema",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := "devdiag.yaml"
		if len(args) > 0 {
			path = args[0]
		}
		data, err := os.ReadFile(path)
		if err != nil {
			result := configValidationOutput{
				Result: configschema.Result{Valid: false, Errors: []string{fmt.Sprintf("read config: %v", err)}},
				Path:   path,
			}
			if renderErr := renderConfigValidation(cmd, result); renderErr != nil {
				return renderErr
			}
			return exitCodeError{code: exitcode.InvalidInput}
		}
		result := configValidationOutput{Result: configschema.ValidateYAML(data), Path: path}
		if err := renderConfigValidation(cmd, result); err != nil {
			return err
		}
		if !result.Valid {
			return exitCodeError{code: exitcode.InvalidInput}
		}
		return nil
	},
}

func renderConfigValidation(cmd *cobra.Command, value configValidationOutput) error {
	switch flagFormat {
	case "json":
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(value)
	case "ndjson":
		return json.NewEncoder(cmd.OutOrStdout()).Encode(value)
	default:
		_, err := fmt.Fprintf(cmd.OutOrStdout(), "%+v\n", value)
		return err
	}
}

func init() {
	configCmd.AddCommand(configValidateCmd)
	rootCmd.AddCommand(configCmd)
}
