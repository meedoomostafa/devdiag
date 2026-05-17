package ssh

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/remote/target"
)

// prefixRunner matches commands by prefix for the sh -lc probe.
type prefixRunner struct {
	connectRes cmdrunner.Result
	factRes    cmdrunner.Result
}

func (r *prefixRunner) Run(ctx context.Context, name string, args ...string) cmdrunner.Result {
	key := name
	for _, a := range args {
		key += " " + a
	}
	// The connect probe is "ssh ... -- printf ok"
	if strings.Contains(key, "printf ok") {
		return r.connectRes
	}
	// The fact probe contains "sh -lc"
	if strings.Contains(key, "sh -lc") {
		return r.factRes
	}
	return cmdrunner.Result{NotFound: true, ExitCode: -1}
}

func TestTransport_Probe_Unreachable(t *testing.T) {
	tr := NewTransport(&target.Target{Kind: target.KindSSH, User: "u", Host: "unreachable"},
		cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"ssh -o ConnectTimeout=5 -o BatchMode=yes u@unreachable -- printf ok": {
				ExitCode: 255, Stderr: "ssh: Could not resolve hostname unreachable: Name or service not known",
			},
		}),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := tr.Probe(ctx)
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if res.Reachable {
		t.Error("expected unreachable")
	}
	if res.Error == "" {
		t.Error("expected error message")
	}
}

func TestTransport_Probe_PermissionDenied(t *testing.T) {
	tr := NewTransport(&target.Target{Kind: target.KindSSH, User: "u", Host: "host"},
		cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
			"ssh -o ConnectTimeout=5 -o BatchMode=yes u@host -- printf ok": {
				ExitCode: 255, Stderr: "Permission denied (publickey,password).",
			},
		}),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := tr.Probe(ctx)
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if res.Reachable {
		t.Error("expected not reachable")
	}
	if res.Error != "ssh permission denied" {
		t.Errorf("error = %q, want ssh permission denied", res.Error)
	}
}

func TestTransport_Probe_OK(t *testing.T) {
	factOut := `/bin/bash
Linux
x86_64
1000
1000
/home/user
/home/user
/bin/sh
/usr/bin/bash


/usr/bin/tmux
/usr/bin/vim

/bin/tar
home_writable
`
	tr := NewTransport(&target.Target{Kind: target.KindSSH, User: "u", Host: "host"},
		&prefixRunner{
			connectRes: cmdrunner.Result{ExitCode: 0, Stdout: "ok"},
			factRes:    cmdrunner.Result{ExitCode: 0, Stdout: factOut},
		},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := tr.Probe(ctx)
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if !res.Reachable {
		t.Fatalf("expected reachable, got error: %s", res.Error)
	}
	if res.Shell != "/bin/bash" {
		t.Errorf("Shell = %q, want /bin/bash", res.Shell)
	}
	if res.OS != "Linux" {
		t.Errorf("OS = %q, want Linux", res.OS)
	}
	if !res.HomeWritable {
		t.Error("expected home writable")
	}
	if !res.Tools["bash"] {
		t.Error("expected bash available")
	}
	if res.Tools["zsh"] {
		t.Error("expected zsh not available")
	}
	if !res.HasTar {
		t.Error("expected tar available")
	}
}

func TestTransport_Probe_HomeNotWritable(t *testing.T) {
	factOut := `/bin/bash
Linux
x86_64
1000
1000
/home/user
/home/user









home_not_writable
`
	tr := NewTransport(&target.Target{Kind: target.KindSSH, User: "u", Host: "host"},
		&prefixRunner{
			connectRes: cmdrunner.Result{ExitCode: 0, Stdout: "ok"},
			factRes:    cmdrunner.Result{ExitCode: 0, Stdout: factOut},
		},
	)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := tr.Probe(ctx)
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if res.HomeWritable {
		t.Error("expected home not writable")
	}
}

func TestClassifySSHError(t *testing.T) {
	tests := []struct {
		stderr string
		code   int
		want   string
	}{
		{"Permission denied (publickey).", 255, "ssh permission denied"},
		{"Could not resolve hostname", 255, "host unreachable"},
		{"No route to host", 255, "host unreachable"},
		{"Connection refused", 255, "connection refused"},
		{"Connection timed out", 255, "connection timed out"},
		{"some other error", 255, "ssh connection error"},
		{"some other", 1, "ssh exited 1: some other"},
	}
	for _, tt := range tests {
		got := classifySSHError(tt.stderr, tt.code)
		if got != tt.want {
			t.Errorf("classifySSHError(%q, %d) = %q, want %q", tt.stderr, tt.code, got, tt.want)
		}
	}
}
