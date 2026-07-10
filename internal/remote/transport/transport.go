package transport

import (
	"context"
)

// RemoteCommand describes a command to run on a remote target.
// Args is the full command line (argv[0] included); Stdin is forwarded to
// the remote process. Timeouts are carried by the context passed to Run.
type RemoteCommand struct {
	Args  []string
	Stdin []byte
}

// RemoteCommandResult captures the outcome of a remote command.
type RemoteCommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
	TimedOut bool
}

// RemoteProbeResult holds facts collected from a remote environment.
type RemoteProbeResult struct {
	Reachable       bool            `json:"reachable"`
	Shell           string          `json:"shell"`
	OS              string          `json:"os"`
	Arch            string          `json:"arch"`
	UID             string          `json:"uid"`
	GID             string          `json:"gid"`
	Home            string          `json:"home"`
	HomeWritable    bool            `json:"home_writable"`
	PWD             string          `json:"pwd"`
	Tools           map[string]bool `json:"tools"`
	HasTar          bool            `json:"has_tar"`
	RestrictedShell bool            `json:"restricted_shell"`
	ReadOnlyFS      bool            `json:"read_only_fs"`
	Error           string          `json:"error,omitempty"`
}

// Transport is the common interface for remote targets.
type Transport interface {
	Kind() string
	Probe(ctx context.Context) (*RemoteProbeResult, error)
	Run(ctx context.Context, cmd RemoteCommand) (*RemoteCommandResult, error)
	Upload(ctx context.Context, localDir, remoteDir string) error
	OpenShell(ctx context.Context, shell string) error
	Close() error
}
