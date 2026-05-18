package cmdrunner

import "context"

// Call records one fake runner invocation.
type Call struct {
	Command string
	Args    []string
	Dir     string
	Stdin   []byte
}

// FakeRunner is a test double that returns pre-programmed results.
type FakeRunner struct {
	// Responses maps "command arg1 arg2 ..." to a Result.
	// The key is built as: name + " " + space-joined args.
	Responses map[string]Result
	Calls     []Call
}

// NewFakeRunner creates a FakeRunner with the given response map.
func NewFakeRunner(responses map[string]Result) *FakeRunner {
	return &FakeRunner{Responses: responses}
}

// Run returns the pre-programmed result for the given command.
// If no match is found, it returns a NotFound result.
func (f *FakeRunner) Run(ctx context.Context, name string, args ...string) Result {
	return f.RunWithOptions(ctx, RunOptions{}, name, args...)
}

// RunWithOptions records options and returns the pre-programmed result.
func (f *FakeRunner) RunWithOptions(ctx context.Context, opts RunOptions, name string, args ...string) Result {
	f.Calls = append(f.Calls, Call{
		Command: name,
		Args:    append([]string(nil), args...),
		Dir:     opts.Dir,
		Stdin:   append([]byte(nil), opts.Stdin...),
	})
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
