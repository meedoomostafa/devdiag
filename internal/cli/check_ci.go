package cli

import (
	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/collectors"
	cicollector "github.com/meedoomostafa/devdiag/internal/collectors/ci"
	composecollector "github.com/meedoomostafa/devdiag/internal/collectors/compose"
	envcollector "github.com/meedoomostafa/devdiag/internal/collectors/env"
	hostcollector "github.com/meedoomostafa/devdiag/internal/collectors/host"
	hostruncollector "github.com/meedoomostafa/devdiag/internal/collectors/hostruntime"
	repocollector "github.com/meedoomostafa/devdiag/internal/collectors/repo"
	runtimecollector "github.com/meedoomostafa/devdiag/internal/collectors/runtime"
	"github.com/meedoomostafa/devdiag/internal/rules"
)

var checkCiCmd = &cobra.Command{
	Use:   "ci [path]",
	Short: "Check CI/local parity",
	Args:  cobra.MaximumNArgs(1),
	RunE: makeCheckRun(func() rules.PolicyEngine { return rules.NewM8Engine() }, func(path string) []collectors.Collector {
		return []collectors.Collector{
			&cicollector.Collector{Root: path},
			&envcollector.Collector{Root: path},
			&composecollector.Collector{Root: path},
			&runtimecollector.Collector{Root: path},
			&hostcollector.Collector{},
			&hostruncollector.Collector{},
			&repocollector.Collector{Root: path},
		}
	}),
}

func init() {
	checkCmd.AddCommand(checkCiCmd)
}
