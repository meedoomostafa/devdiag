package schema

// CollectorStatus represents the result status of a single collector.
type CollectorStatus string

const (
	CollectorOK              CollectorStatus = "ok"
	CollectorPartial         CollectorStatus = "partial"
	CollectorTimeout         CollectorStatus = "timeout"
	CollectorPermissionDenied CollectorStatus = "permission_denied"
	CollectorUnavailable     CollectorStatus = "unavailable"
	CollectorFailed          CollectorStatus = "failed"
)

// CollectorResult is the output of a single collector.
type CollectorResult struct {
	Name       string          `json:"collector"`
	Status     CollectorStatus `json:"status"`
	TimeoutMs  int             `json:"timeout_ms,omitempty"`
	Partial    bool            `json:"partial,omitempty"`
	Evidence   []Evidence      `json:"evidence,omitempty"`
	Notes      []string        `json:"notes,omitempty"`
}
