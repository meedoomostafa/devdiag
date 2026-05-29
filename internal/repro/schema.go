package repro

import "time"

// ReproResult is the structured output of a repro run.
type ReproResult struct {
	Command          string           `json:"command"`
	Args             []string         `json:"args,omitempty"`
	WorkingDir       string           `json:"working_dir"`
	EnvKeys          []string         `json:"env_keys,omitempty"`
	SensitiveEnvKeys []string         `json:"sensitive_env_keys,omitempty"`
	ExitCode         int              `json:"exit_code"`
	StartTime        time.Time        `json:"start_time"`
	EndTime          time.Time        `json:"end_time"`
	DurationMs       int64            `json:"duration_ms"`
	TimedOut         bool             `json:"timed_out,omitempty"`
	StdoutPreview    string           `json:"stdout_preview,omitempty"`
	StderrPreview    string           `json:"stderr_preview,omitempty"`
	Truncated        bool             `json:"truncated,omitempty"`
	OriginalBytes    int64            `json:"original_bytes,omitempty"`
	StoredBytes      int64            `json:"stored_bytes,omitempty"`
	Classifications  []Classification `json:"classifications,omitempty"`
	Timeline         []ReproEvent     `json:"timeline,omitempty"`
}

// Classification is a pattern match from the log classifier.
type Classification struct {
	Kind         string  `json:"kind"`
	SourceStream string  `json:"source_stream"` // "stdout" or "stderr"
	Confidence   float64 `json:"confidence"`
	PatternID    string  `json:"pattern_id"`
	Excerpt      string  `json:"excerpt"`
}

// ReproEvent is a single point in the command timeline.
type ReproEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`   // e.g. "start", "stdout", "stderr", "timeout", "exit"
	Detail    string    `json:"detail"` // e.g. first line of output or exit code
}
