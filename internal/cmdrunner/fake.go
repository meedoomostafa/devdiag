package cmdrunner

import "context"

// FakeRunner is a test double that returns pre-programmed results.
type FakeRunner struct {
	// Responses maps "command arg1 arg2 ..." to a Result.
	// The key is built as: name + " " + space-joined args.
	Responses map[string]Result
}

// NewFakeRunner creates a FakeRunner with the given response map.
func NewFakeRunner(responses map[string]Result) *FakeRunner {
	return &FakeRunner{Responses: responses}
}

// Run returns the pre-programmed result for the given command.
// If no match is found, it returns a NotFound result.
func (f *FakeRunner) Run(ctx context.Context, name string, args ...string) Result {
	key := name
	for _, a := range args {
		key += " " + a
	}
	if r, ok := f.Responses[key]; ok {
		return r
	}
	return Result{
		Command:  name,
		Args:     append([]string(nil), args...),
		NotFound: true,
		ExitCode: -1,
	}
}
