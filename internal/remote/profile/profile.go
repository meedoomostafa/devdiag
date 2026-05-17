package profile

import "strings"

// RemoteProfile defines what DevDiag injects into the remote target.
type RemoteProfile struct {
	SchemaVersion string              `json:"schema_version"`
	Name          string              `json:"name"`
	Description   string              `json:"description"`
	Files         []RemoteProfileFile `json:"files"`
	Env           []RemoteEnvVar      `json:"env,omitempty"`
	ShellHooks    []ShellHook         `json:"shell_hooks,omitempty"`
	Requirements  ProfileRequirements `json:"requirements,omitempty"`
}

// RemoteProfileFile describes a single file to inject.
type RemoteProfileFile struct {
	LogicalName string `json:"logical_name"`
	TargetPath  string `json:"target_path"`
	Mode        string `json:"mode"` // e.g. "0644", "0755"
	Content     string `json:"content"`
	OnConflict  string `json:"on_conflict"` // skip, backup, fail
	Managed     bool   `json:"managed"`
}

// RemoteEnvVar is an environment variable to set.
type RemoteEnvVar struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ShellHook is a snippet to source for a specific shell.
type ShellHook struct {
	Shell   string `json:"shell"` // sh, bash, zsh, fish
	Content string `json:"content"`
}

// ProfileRequirements describes runtime requirements for a profile.
type ProfileRequirements struct {
	NeedsWritableHome bool     `json:"needs_writable_home"`
	NeedsCommands     []string `json:"needs_commands,omitempty"`
}

// Minimal returns the built-in minimal profile.
func Minimal() *RemoteProfile {
	return &RemoteProfile{
		SchemaVersion: "0.1",
		Name:          "minimal",
		Description:   "Minimal safe developer environment helpers",
		Files: []RemoteProfileFile{
			{
				LogicalName: "env.sh",
				TargetPath:  "env.sh",
				Mode:        "0644",
				OnConflict:  "skip",
				Managed:     true,
				Content: `# DevDiag temporary remote environment
# Generated for this session only.

export DEVDDIR="${DEVDDIR:-$HOME/.devdiag/remote/__SESSION_ID__}"
export PATH="$DEVDDIR/bin:$PATH"

if [ -f "$DEVDDIR/aliases.sh" ]; then
  . "$DEVDDIR/aliases.sh"
fi

if [ -n "$PS1" ]; then
  PS1="[devdiag] $PS1"
fi
`,
			},
			{
				LogicalName: "aliases.sh",
				TargetPath:  "aliases.sh",
				Mode:        "0644",
				OnConflict:  "skip",
				Managed:     true,
				Content: `alias ll='ls -la'
alias grep='grep --color=auto'
alias dd-path='printf "%s\n" "$PATH" | tr ":" "\n"'
alias dd-here='pwd; id; uname -a'
`,
			},
			{
				LogicalName: "bin/dd-path",
				TargetPath:  "bin/dd-path",
				Mode:        "0755",
				OnConflict:  "skip",
				Managed:     true,
				Content: `#!/bin/sh
printf '%s\n' "$PATH" | tr ':' '\n'
`,
			},
			{
				LogicalName: "bin/dd-ports",
				TargetPath:  "bin/dd-ports",
				Mode:        "0755",
				OnConflict:  "skip",
				Managed:     true,
				Content: `#!/bin/sh
if command -v ss >/dev/null 2>&1; then
  ss -ltnp 2>/dev/null || ss -ltn 2>/dev/null
elif command -v netstat >/dev/null 2>&1; then
  netstat -ltn 2>/dev/null
else
  echo "no ss or netstat available"
  exit 1
fi
`,
			},
			{
				LogicalName: "bin/dd-proc",
				TargetPath:  "bin/dd-proc",
				Mode:        "0755",
				OnConflict:  "skip",
				Managed:     true,
				Content: `#!/bin/sh
if command -v ps >/dev/null 2>&1; then
  ps aux 2>/dev/null || ps 2>/dev/null
else
  echo "ps unavailable"
  exit 1
fi
`,
			},
			{
				LogicalName: "bin/dd-clean",
				TargetPath:  "bin/dd-clean",
				Mode:        "0755",
				OnConflict:  "skip",
				Managed:     true,
				Content: `#!/bin/sh
# Print the DevDiag session root for manual cleanup.
if [ -n "$DEVDDIR" ]; then
  echo "$DEVDDIR"
else
  echo "DEVDDIR not set; no active DevDiag session"
  exit 1
fi
`,
			},
			{
				LogicalName: "tmux.conf",
				TargetPath:  "tmux.conf",
				Mode:        "0644",
				OnConflict:  "skip",
				Managed:     true,
				Content: `set -g history-limit 10000
set -g mouse on
`,
			},
		},
		Requirements: ProfileRequirements{
			NeedsWritableHome: true,
			NeedsCommands:     []string{"sh"},
		},
	}
}

// SubstituteSessionID replaces __SESSION_ID__ in all profile file contents.
func (p *RemoteProfile) SubstituteSessionID(sessionID string) {
	for i := range p.Files {
		p.Files[i].Content = substituteSessionID(p.Files[i].Content, sessionID)
	}
	for i := range p.ShellHooks {
		p.ShellHooks[i].Content = substituteSessionID(p.ShellHooks[i].Content, sessionID)
	}
}

func substituteSessionID(content, sessionID string) string {
	return strings.ReplaceAll(content, "__SESSION_ID__", sessionID)
}
