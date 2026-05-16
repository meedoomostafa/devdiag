package rules

import (
	"testing"

	"github.com/meedoomostafa/devdiag/internal/graph"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestM1Engine_EnvRules(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "env",
				Evidence: []schema.Evidence{
					{Source: ".env.example", Value: "keys: DATABASE_URL, API_KEY"},
					{Source: ".env", Value: "missing"},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	var hasEnv001 bool
	for _, f := range findings {
		if f.ID == "F-ENV-001" {
			hasEnv001 = true
		}
	}
	if !hasEnv001 {
		t.Errorf("expected F-ENV-001 finding, got: %v", findings)
	}
}

func TestM1Engine_RepoRules_MultipleLockfiles(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "repo",
				Evidence: []schema.Evidence{
					{Source: "lockfiles", Value: "package-lock.json, yarn.lock"},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	var hasPM001 bool
	for _, f := range findings {
		if f.ID == "F-PM-001" {
			hasPM001 = true
		}
	}
	if !hasPM001 {
		t.Errorf("expected F-PM-001 finding, got: %v", findings)
	}
}

func TestM1Engine_GitRules_TrackedEnv(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "git",
				Evidence: []schema.Evidence{
					{Source: "git_tracked_env", Value: ".env"},
					{Source: "git_env_exists", Value: "true"},
					{Source: "git_env_ignored", Value: "false"},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	var hasGit001, hasGit002 bool
	for _, f := range findings {
		if f.ID == "F-GIT-001" {
			hasGit001 = true
		}
		if f.ID == "F-GIT-002" {
			hasGit002 = true
		}
	}
	if !hasGit001 {
		t.Errorf("expected F-GIT-001 finding")
	}
	if !hasGit002 {
		t.Errorf("expected F-GIT-002 finding")
	}
}

func TestM1Engine_ComposeRules(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "compose",
				Evidence: []schema.Evidence{
					{Source: "compose.yaml:17", Value: "services.api.environment.DATABASE_URL references ${DATABASE_URL}"},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	var hasEnv002 bool
	for _, f := range findings {
		if f.ID == "F-ENV-002" {
			hasEnv002 = true
		}
	}
	if !hasEnv002 {
		t.Errorf("expected F-ENV-002 finding, got: %v", findings)
	}
}

func TestM1Engine_HostRuntimeRules_Mismatch(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "runtime",
				Evidence: []schema.Evidence{
					{Source: ".nvmrc", Value: "node 20.11.0"},
				},
			},
			{
				Name: "host_runtime",
				Evidence: []schema.Evidence{
					{Source: "host_node_version", Value: "18.17.0"},
					{Source: "host_node_path", Value: "/usr/bin/node"},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	var hasRuntime001 bool
	for _, f := range findings {
		if f.ID == "F-RUNTIME-001" {
			hasRuntime001 = true
		}
	}
	if !hasRuntime001 {
		t.Errorf("expected F-RUNTIME-001 finding, got: %v", findings)
	}
}

func TestM1Engine_HostRuntimeRules_Missing(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "runtime",
				Evidence: []schema.Evidence{
					{Source: ".nvmrc", Value: "node 20.11.0"},
				},
			},
			{
				Name: "host_runtime",
				Evidence: []schema.Evidence{
					{Source: "host_node_missing", Value: "true"},
					{Source: "host_node_path", Value: ""},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	var hasRuntime003 bool
	for _, f := range findings {
		if f.ID == "F-RUNTIME-003" {
			hasRuntime003 = true
		}
	}
	if !hasRuntime003 {
		t.Errorf("expected F-RUNTIME-003 finding, got: %v", findings)
	}
}

func TestM1Engine_HostRuntimeRules_NormalizedMatch(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "runtime",
				Evidence: []schema.Evidence{
					{Source: ".nvmrc", Value: "node 20.11.0"},
				},
			},
			{
				Name: "host_runtime",
				Evidence: []schema.Evidence{
					{Source: "host_node_version", Value: "20.11.1"},
					{Source: "host_node_path", Value: "/usr/bin/node"},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	// Patch-level difference should not produce mismatch
	for _, f := range findings {
		if f.ID == "F-RUNTIME-001" {
			t.Errorf("unexpected F-RUNTIME-001 for patch-level match, got: %v", findings)
		}
	}
}

func TestM1Engine_HostRuntimeRules_LTSNoMismatch(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "runtime",
				Evidence: []schema.Evidence{
					{Source: ".nvmrc", Value: "node lts/*"},
				},
			},
			{
				Name: "host_runtime",
				Evidence: []schema.Evidence{
					{Source: "host_node_version", Value: "18.17.0"},
					{Source: "host_node_path", Value: "/usr/bin/node"},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	// lts/* should not produce a hard mismatch
	for _, f := range findings {
		if f.ID == "F-RUNTIME-001" {
			t.Errorf("unexpected F-RUNTIME-001 for lts/*, got: %v", findings)
		}
	}
}

func TestM1Engine_DiskRules_Pressure(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "disk",
				Evidence: []schema.Evidence{
					{Source: "host_disk_free_bytes", Value: "536870912"}, // 0.5 GiB
					{Source: "host_disk_free_pct", Value: "1.5"},
					{Source: "host_disk_free_inodes_pct", Value: "5.0"},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	var hasDisk001 bool
	for _, f := range findings {
		if f.ID == "F-DISK-001" {
			hasDisk001 = true
		}
	}
	if !hasDisk001 {
		t.Errorf("expected F-DISK-001 finding, got: %v", findings)
	}
}

func TestM1Engine_DiskRules_Healthy(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "disk",
				Evidence: []schema.Evidence{
					{Source: "host_disk_free_bytes", Value: "10737418240"}, // 10 GiB
					{Source: "host_disk_free_pct", Value: "25.0"},
					{Source: "host_disk_free_inodes_pct", Value: "30.0"},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	for _, f := range findings {
		if f.ID == "F-DISK-001" {
			t.Errorf("unexpected F-DISK-001 for healthy disk, got: %v", findings)
		}
	}
}

func TestM1Engine_NetworkRules_Proxy(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "network",
				Evidence: []schema.Evidence{
					{Source: "host_proxy_env", Value: "HTTP_PROXY=set"},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	var hasNet001 bool
	for _, f := range findings {
		if f.ID == "F-NET-001" {
			hasNet001 = true
		}
	}
	if !hasNet001 {
		t.Errorf("expected F-NET-001 finding, got: %v", findings)
	}
}

func TestM1Engine_SystemdRules_DockerInactive(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "systemd",
				Evidence: []schema.Evidence{
					{Source: "host_docker_service", Value: "inactive"},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	var hasSVC001 bool
	for _, f := range findings {
		if f.ID == "F-SVC-001" {
			hasSVC001 = true
		}
	}
	if !hasSVC001 {
		t.Errorf("expected F-SVC-001 finding, got: %v", findings)
	}
}

func TestM1Engine_PermissionRules_NotExecutable(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "permission",
				Evidence: []schema.Evidence{
					{Source: "host_script_not_executable", Value: "build.sh"},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	var hasFS001 bool
	for _, f := range findings {
		if f.ID == "F-FS-001" {
			hasFS001 = true
		}
	}
	if !hasFS001 {
		t.Errorf("expected F-FS-001 finding, got: %v", findings)
	}
}

func TestM1Engine_PortRules_Conflict(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "compose",
				Evidence: []schema.Evidence{
					{Source: "compose_host_port", Value: "5432"},
				},
			},
			{
				Name: "port",
				Evidence: []schema.Evidence{
					{Source: "host_listen_port_0.0.0.0", Value: "5432"},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	var hasPort001 bool
	for _, f := range findings {
		if f.ID == "F-PORT-001" {
			hasPort001 = true
		}
	}
	if !hasPort001 {
		t.Errorf("expected F-PORT-001 finding, got: %v", findings)
	}
}
