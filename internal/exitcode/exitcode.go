package exitcode

// Exit codes are part of the public CLI contract and must not change casually.
type Code int

const (
	Success              Code = 0
	FindingsExist        Code = 1
	InvalidInput         Code = 2
	CollectorPartial     Code = 3
	PermissionDenied     Code = 4
	UnsafeRefused        Code = 5
	ReproFailed          Code = 6
	TraceUnavailable     Code = 7
	InternalError        Code = 8
)

func (c Code) Int() int { return int(c) }
