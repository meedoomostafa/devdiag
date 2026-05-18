package cmdrunner

import (
	"context"
	"testing"
	"time"
)

func TestRealRunnerEcho(t *testing.T) {
	r := NewRealRunner()
	ctx := context.Background()
	res := r.Run(ctx, "echo", "hello")
	if res.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", res.ExitCode)
	}
	if res.Stdout != "hello\n" {
		t.Fatalf("expected stdout 'hello\\n', got %q", res.Stdout)
	}
	if res.NotFound {
		t.Fatal("expected NotFound=false")
	}
	if res.TimedOut {
		t.Fatal("expected TimedOut=false")
	}
}

func TestRealRunnerCommandNotFound(t *testing.T) {
	r := NewRealRunner()
	ctx := context.Background()
	res := r.Run(ctx, "devdiag_nonexistent_command_12345")
	if !res.NotFound {
		t.Fatal("expected NotFound=true")
	}
	if res.ExitCode != -1 {
		t.Fatalf("expected exit code -1, got %d", res.ExitCode)
	}
}

func TestRealRunnerTimeout(t *testing.T) {
	r := NewRealRunner()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	res := r.Run(ctx, "sleep", "10")
	if !res.TimedOut {
		t.Fatalf("expected TimedOut=true, got exit=%d", res.ExitCode)
	}
}

func TestFakeRunner(t *testing.T) {
	f := NewFakeRunner(map[string]Result{
		"nvidia-smi --query-gpu=name --format=csv,noheader": {
			Command:  "nvidia-smi",
			ExitCode: 0,
			Stdout:   "NVIDIA GeForce RTX 4090\n",
		},
	})
	ctx := context.Background()
	res := f.Run(ctx, "nvidia-smi", "--query-gpu=name", "--format=csv,noheader")
	if res.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", res.ExitCode)
	}
	if res.Stdout != "NVIDIA GeForce RTX 4090\n" {
		t.Fatalf("unexpected stdout: %q", res.Stdout)
	}
}

func TestFakeRunnerNotFound(t *testing.T) {
	f := NewFakeRunner(map[string]Result{})
	ctx := context.Background()
	res := f.Run(ctx, "unknown-cmd")
	if !res.NotFound {
		t.Fatal("expected NotFound=true")
	}
}

func TestFakeRunnerRecordsRunOptions(t *testing.T) {
	f := NewFakeRunner(map[string]Result{
		"docker compose config --format json": {
			Command:  "docker",
			ExitCode: 0,
			Stdout:   `{"services":{}}`,
		},
	})

	res := RunWithOptions(context.Background(), f, RunOptions{
		Dir:   "/tmp/project",
		Stdin: []byte("manifest"),
	}, "docker", "compose", "config", "--format", "json")

	if res.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", res.ExitCode)
	}
	if len(f.Calls) != 1 {
		t.Fatalf("expected 1 recorded call, got %d", len(f.Calls))
	}
	call := f.Calls[0]
	if call.Dir != "/tmp/project" {
		t.Fatalf("expected dir /tmp/project, got %q", call.Dir)
	}
	if string(call.Stdin) != "manifest" {
		t.Fatalf("expected stdin to be recorded, got %q", string(call.Stdin))
	}
}
