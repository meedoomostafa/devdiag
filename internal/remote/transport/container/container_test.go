package container

import (
	"context"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/remote/target"
	"github.com/meedoomostafa/devdiag/internal/remote/transport"
)

func TestNewTransportWithRunner_AutoDetectsDocker(t *testing.T) {
	runner := cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
		"docker inspect --format {{.Id}} api": {
			Command:  "docker",
			ExitCode: 0,
			Stdout:   "abc123\n",
		},
	})

	tr, err := NewTransportWithRunner(&target.Target{Kind: target.KindContainer, Runtime: "auto", Container: "api"}, runner)
	if err != nil {
		t.Fatalf("NewTransportWithRunner error: %v", err)
	}
	if tr.Runtime != "docker" {
		t.Fatalf("runtime = %q, want docker", tr.Runtime)
	}
	if len(runner.Calls) != 1 {
		t.Fatalf("expected 1 runner call, got %d", len(runner.Calls))
	}
}

func TestNewTransportWithRunner_AutoDetectsPodmanAfterDockerMiss(t *testing.T) {
	runner := cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
		"docker inspect --format {{.Id}} api": {
			Command:  "docker",
			ExitCode: 1,
			Stderr:   "No such object: api",
		},
		"podman inspect --format {{.Id}} api": {
			Command:  "podman",
			ExitCode: 0,
			Stdout:   "def456\n",
		},
	})

	tr, err := NewTransportWithRunner(&target.Target{Kind: target.KindContainer, Runtime: "auto", Container: "api"}, runner)
	if err != nil {
		t.Fatalf("NewTransportWithRunner error: %v", err)
	}
	if tr.Runtime != "podman" {
		t.Fatalf("runtime = %q, want podman", tr.Runtime)
	}
	if len(runner.Calls) != 2 {
		t.Fatalf("expected 2 runner calls, got %d", len(runner.Calls))
	}
}

func TestTransportRunUsesCommandRunnerWithStdin(t *testing.T) {
	runner := cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
		"docker exec -i api sh -lc cat": {
			Command:  "docker",
			ExitCode: 0,
			Stdout:   "manifest",
		},
	})
	tr := &Transport{
		Target:  &target.Target{Kind: target.KindContainer, Runtime: "docker", Container: "api"},
		Runtime: "docker",
		Runner:  runner,
	}

	res, err := tr.Run(context.Background(), transport.RemoteCommand{
		Args:  []string{"sh", "-lc", "cat"},
		Stdin: []byte("manifest"),
	})
	if err != nil {
		t.Fatalf("Run error: %v", err)
	}
	if res.Stdout != "manifest" {
		t.Fatalf("stdout = %q, want manifest", res.Stdout)
	}
	if len(runner.Calls) != 1 {
		t.Fatalf("expected 1 runner call, got %d", len(runner.Calls))
	}
	if string(runner.Calls[0].Stdin) != "manifest" {
		t.Fatalf("stdin = %q, want manifest", string(runner.Calls[0].Stdin))
	}
}

func TestTransportUploadUsesCommandRunner(t *testing.T) {
	runner := cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
		"docker exec api mkdir -p /tmp/devdiag": {
			Command:  "docker",
			ExitCode: 0,
		},
		"docker cp /tmp/local/. api:/tmp/devdiag": {
			Command:  "docker",
			ExitCode: 0,
		},
	})
	tr := &Transport{
		Target:  &target.Target{Kind: target.KindContainer, Runtime: "docker", Container: "api"},
		Runtime: "docker",
		Runner:  runner,
	}

	if err := tr.Upload(context.Background(), "/tmp/local", "/tmp/devdiag"); err != nil {
		t.Fatalf("Upload error: %v", err)
	}
	if len(runner.Calls) != 2 {
		t.Fatalf("expected 2 runner calls, got %d", len(runner.Calls))
	}
}

func TestParseFactOutput(t *testing.T) {
	stdout := `/bin/sh
Linux
x86_64
0
0
/
/
/bin/sh






/bin/tar
tmp_writable
`
	res := &transport.RemoteProbeResult{Tools: make(map[string]bool)}
	parseFactOutput(res, stdout)

	if res.Shell != "/bin/sh" {
		t.Errorf("Shell = %q, want /bin/sh", res.Shell)
	}
	if res.OS != "Linux" {
		t.Errorf("OS = %q, want Linux", res.OS)
	}
	if !res.HomeWritable {
		t.Error("expected tmp writable")
	}
	if !res.Tools["sh"] {
		t.Error("expected sh available")
	}
	if res.Tools["bash"] {
		t.Error("expected bash not available")
	}
	if !res.HasTar {
		t.Error("expected tar available")
	}
}

func TestParseFactOutput_ReadOnly(t *testing.T) {
	stdout := `/bin/sh
Linux
x86_64
0
0
/
/








tmp_not_writable
`
	res := &transport.RemoteProbeResult{Tools: make(map[string]bool)}
	parseFactOutput(res, stdout)

	if res.HomeWritable {
		t.Error("expected tmp not writable")
	}
}
