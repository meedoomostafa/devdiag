package k8s

import (
	"context"
	"strings"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/remote/target"
	"github.com/meedoomostafa/devdiag/internal/remote/transport"
)

func TestKubectlBaseArgsUseContextNamespaceAndContainer(t *testing.T) {
	tr := &Transport{
		Target: &target.Target{
			Kind:      target.KindK8s,
			Context:   "prod",
			Namespace: "api",
			Pod:       "web-0",
		},
		Container: "app",
	}

	args := tr.kubectlExecArgs(false, false, "sh", "-lc", "true")
	got := strings.Join(args, " ")
	for _, want := range []string{"--context prod", "-n api", "exec", "web-0", "-c app", "-- sh -lc true"} {
		if !strings.Contains(got, want) {
			t.Fatalf("kubectl args missing %q: %v", want, args)
		}
	}
}

func TestProbeUsesKubectlExecAndParsesFacts(t *testing.T) {
	runner := cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
		"kubectl -n default exec api-pod -- printf ok": {
			Command:  "kubectl",
			ExitCode: 0,
			Stdout:   "ok",
		},
		"kubectl -n default exec api-pod -- sh -lc " + factScript: {
			Command:  "kubectl",
			ExitCode: 0,
			Stdout:   "/bin/sh\nLinux\nx86_64\n1000\n1000\n/work\n/home/app\n/bin/sh\n/bin/bash\n\n\n\n\n\n/bin/tar\ntmp_writable\n",
		},
	})
	tr := NewTransportWithRunner(&target.Target{Kind: target.KindK8s, Namespace: "default", Pod: "api-pod"}, "", runner)

	probe, err := tr.Probe(context.Background())
	if err != nil {
		t.Fatalf("Probe error: %v", err)
	}
	if !probe.Reachable {
		t.Fatalf("probe reachable = false, want true; probe=%+v", probe)
	}
	if !probe.HasTar || !probe.HomeWritable {
		t.Fatalf("probe tar/home writable = %v/%v, want true/true", probe.HasTar, probe.HomeWritable)
	}
	if probe.Tools["bash"] != true {
		t.Fatalf("probe tools missing bash: %+v", probe.Tools)
	}
}

func TestRunUsesKubectlExecWithStdin(t *testing.T) {
	runner := cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
		"kubectl -n default exec -i api-pod -- sh -lc cat": {
			Command:  "kubectl",
			ExitCode: 0,
			Stdout:   "manifest",
		},
	})
	tr := NewTransportWithRunner(&target.Target{Kind: target.KindK8s, Namespace: "default", Pod: "api-pod"}, "", runner)

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
	if got := string(runner.Calls[0].Stdin); got != "manifest" {
		t.Fatalf("stdin = %q, want manifest", got)
	}
}

func TestUploadTarsLocalDirIntoKubectlExec(t *testing.T) {
	runner := cmdrunner.NewFakeRunner(map[string]cmdrunner.Result{
		"tar -cf - .": {
			Command:  "tar",
			ExitCode: 0,
			Stdout:   "tar-bytes",
		},
		"kubectl -n default exec -i api-pod -- sh -lc mkdir -p /tmp/devdiag-remote/s1 && tar -C /tmp/devdiag-remote/s1 -xf -": {
			Command:  "kubectl",
			ExitCode: 0,
		},
	})
	tr := NewTransportWithRunner(&target.Target{Kind: target.KindK8s, Namespace: "default", Pod: "api-pod"}, "", runner)

	if err := tr.Upload(context.Background(), "/tmp/stage", "/tmp/devdiag-remote/s1"); err != nil {
		t.Fatalf("Upload error: %v", err)
	}
	if len(runner.Calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(runner.Calls))
	}
	if runner.Calls[0].Command != "tar" || runner.Calls[0].Dir != "/tmp/stage" {
		t.Fatalf("tar call = %+v, want dir /tmp/stage", runner.Calls[0])
	}
	if got := string(runner.Calls[1].Stdin); got != "tar-bytes" {
		t.Fatalf("kubectl stdin = %q, want tar-bytes", got)
	}
}
