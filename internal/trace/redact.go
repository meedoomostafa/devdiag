package trace

import (
	"github.com/meedoomostafa/devdiag/internal/redact"
)

// RedactResult returns a deep copy of res with sensitive string fields redacted.
// Raw events must never be persisted or printed unredacted.
// NOTE: Syscall names, errno values, PID, Timestamp, and Duration are NOT
// redacted because they contain no secrets and are needed for diagnosis.
func RedactResult(res *Result, eng *redact.Engine) *Result {
	out := *res
	out.Command = eng.RedactString(out.Command, "trace_command")
	out.Args = make([]string, len(res.Args))
	for i, a := range res.Args {
		out.Args[i] = eng.RedactString(a, "trace_arg")
	}
	out.Events = make([]Event, len(res.Events))
	for i, ev := range res.Events {
		out.Events[i] = ev
		// Do NOT redact Syscall, Error, PID, Timestamp, Duration
		out.Events[i].Args = make([]string, len(ev.Args))
		for j, a := range ev.Args {
			out.Events[i].Args[j] = eng.RedactString(a, "trace_arg")
		}
		out.Events[i].Result = eng.RedactString(ev.Result, "trace_result")
	}
	out.Notes = make([]string, len(res.Notes))
	for i, n := range res.Notes {
		out.Notes[i] = eng.RedactString(n, "trace_note")
	}
	return &out
}
