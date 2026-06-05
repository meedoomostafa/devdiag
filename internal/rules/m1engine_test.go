package rules

import (
	"strings"
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
	// 1. Missing everywhere (should emit finding)
	t.Run("missing everywhere", func(t *testing.T) {
		engine := NewM1Engine()
		snapshot := graph.NormalizedSnapshot{
			Collectors: []schema.CollectorResult{
				{
					Name: "compose",
					Evidence: []schema.Evidence{
						{Source: "compose.yaml:17", Value: "services.api.environment.DB_MISSING_EVERYWHERE references ${DB_MISSING_EVERYWHERE}"},
					},
				},
			},
		}
		findings, err := engine.Evaluate(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, f := range findings {
			if f.ID == "F-ENV-002" && strings.Contains(f.Title, "DB_MISSING_EVERYWHERE") {
				found = true
			}
		}
		if !found {
			t.Error("expected F-ENV-002 finding for DB_MISSING_EVERYWHERE")
		}
	})

	// 2. Defined in .env (should not emit finding)
	t.Run("defined in .env", func(t *testing.T) {
		engine := NewM1Engine()
		snapshot := graph.NormalizedSnapshot{
			Collectors: []schema.CollectorResult{
				{
					Name: "env",
					Evidence: []schema.Evidence{
						{Source: ".env", Value: "keys: DB_IN_DOTENV, OTHER"},
					},
				},
				{
					Name: "compose",
					Evidence: []schema.Evidence{
						{Source: "compose.yaml:17", Value: "services.api.environment.DB_IN_DOTENV references ${DB_IN_DOTENV}"},
					},
				},
			},
		}
		findings, err := engine.Evaluate(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range findings {
			if f.ID == "F-ENV-002" && strings.Contains(f.Title, "DB_IN_DOTENV") {
				t.Error("unexpected F-ENV-002 finding for DB_IN_DOTENV (defined in .env)")
			}
		}
	})

	// 3. Defined in .env.local (should not emit finding)
	t.Run("defined in .env.local", func(t *testing.T) {
		engine := NewM1Engine()
		snapshot := graph.NormalizedSnapshot{
			Collectors: []schema.CollectorResult{
				{
					Name: "env",
					Evidence: []schema.Evidence{
						{Source: ".env.local", Value: "keys: DB_IN_ENVLOCAL"},
					},
				},
				{
					Name: "compose",
					Evidence: []schema.Evidence{
						{Source: "compose.yaml:17", Value: "services.api.environment.DB_IN_ENVLOCAL references ${DB_IN_ENVLOCAL}"},
					},
				},
			},
		}
		findings, err := engine.Evaluate(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range findings {
			if f.ID == "F-ENV-002" && strings.Contains(f.Title, "DB_IN_ENVLOCAL") {
				t.Error("unexpected F-ENV-002 finding for DB_IN_ENVLOCAL (defined in .env.local)")
			}
		}
	})

	// 4. Defined in process env (should no longer suppress)
	t.Run("defined in process env", func(t *testing.T) {
		const varName = "DB_IN_PROCESS_ENV_TEST"
		t.Setenv(varName, "somevalue")

		engine := NewM1Engine()
		snapshot := graph.NormalizedSnapshot{
			Collectors: []schema.CollectorResult{
				{
					Name: "compose",
					Evidence: []schema.Evidence{
						{Source: "compose.yaml:17", Value: "services.api.environment.DB_IN_PROCESS_ENV_TEST references ${DB_IN_PROCESS_ENV_TEST}"},
					},
				},
			},
		}
		findings, err := engine.Evaluate(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, f := range findings {
			if f.ID == "F-ENV-002" && strings.Contains(f.Title, varName) {
				found = true
			}
		}
		if !found {
			t.Errorf("expected F-ENV-002 finding for %s (process environment should be ignored)", varName)
		}
	})

	// 5. Default/alternative forms (should not emit finding)
	t.Run("default or alternative forms", func(t *testing.T) {
		engine := NewM1Engine()
		snapshot := graph.NormalizedSnapshot{
			Collectors: []schema.CollectorResult{
				{
					Name: "compose",
					Evidence: []schema.Evidence{
						{Source: "compose.yaml:10", Value: "services.api.ports[0] references ${PORT:-5432}"},
						{Source: "compose.yaml:11", Value: "services.api.ports[1] references ${PORT-5432}"},
						{Source: "compose.yaml:12", Value: "services.api.ports[2] references ${PORT:+5432}"},
						{Source: "compose.yaml:13", Value: "services.api.ports[3] references ${PORT+5432}"},
					},
				},
			},
		}
		findings, err := engine.Evaluate(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range findings {
			if f.ID == "F-ENV-002" {
				t.Errorf("unexpected F-ENV-002 finding: %v", f)
			}
		}
	})

	// 6. Error check modifiers (should emit finding if missing, should not if defined)
	t.Run("error check modifiers missing", func(t *testing.T) {
		engine := NewM1Engine()
		snapshot := graph.NormalizedSnapshot{
			Collectors: []schema.CollectorResult{
				{
					Name: "compose",
					Evidence: []schema.Evidence{
						{Source: "compose.yaml:17", Value: "services.api.environment.DB_REQ references ${DB_REQ:?required}"},
					},
				},
			},
		}
		findings, err := engine.Evaluate(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, f := range findings {
			if f.ID == "F-ENV-002" && strings.Contains(f.Title, "DB_REQ") {
				found = true
			}
		}
		if !found {
			t.Error("expected F-ENV-002 finding for DB_REQ:?required")
		}
	})

	t.Run("error check modifiers defined", func(t *testing.T) {
		engine := NewM1Engine()
		snapshot := graph.NormalizedSnapshot{
			Collectors: []schema.CollectorResult{
				{
					Name: "env",
					Evidence: []schema.Evidence{
						{Source: ".env", Value: "keys: DB_REQ"},
					},
				},
				{
					Name: "compose",
					Evidence: []schema.Evidence{
						{Source: "compose.yaml:17", Value: "services.api.environment.DB_REQ references ${DB_REQ:?required}"},
					},
				},
			},
		}
		findings, err := engine.Evaluate(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range findings {
			if f.ID == "F-ENV-002" && strings.Contains(f.Title, "DB_REQ") {
				t.Error("unexpected F-ENV-002 finding for DB_REQ when defined")
			}
		}
	})

	// 7. Compose metadata (should not emit finding)
	t.Run("compose metadata ignored", func(t *testing.T) {
		engine := NewM1Engine()
		snapshot := graph.NormalizedSnapshot{
			Collectors: []schema.CollectorResult{
				{
					Name: "compose",
					Evidence: []schema.Evidence{
						{Source: "compose_host_port", Value: "8080"},
						{Source: "compose_service__api__image", Value: "node:18"},
					},
				},
			},
		}
		findings, err := engine.Evaluate(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range findings {
			if f.ID == "F-ENV-002" {
				t.Errorf("unexpected F-ENV-002 finding for compose metadata: %v", f)
			}
		}
	})

	// 8. Grouping multiple references
	t.Run("grouped findings", func(t *testing.T) {
		engine := NewM1Engine()
		snapshot := graph.NormalizedSnapshot{
			Collectors: []schema.CollectorResult{
				{
					Name: "compose",
					Evidence: []schema.Evidence{
						{Source: "compose.yaml:10", Value: "services.api.environment.DB references ${DB}"},
						{Source: "compose.yaml:20", Value: "services.worker.environment.DB references ${DB}"},
					},
				},
			},
		}
		findings, err := engine.Evaluate(snapshot)
		if err != nil {
			t.Fatal(err)
		}
		var dbFindings []schema.Finding
		for _, f := range findings {
			if f.ID == "F-ENV-002" && strings.Contains(f.Title, "DB") {
				dbFindings = append(dbFindings, f)
			}
		}
		if len(dbFindings) != 1 {
			t.Fatalf("expected exactly 1 grouped finding for DB, got %d", len(dbFindings))
		}
		if len(dbFindings[0].Evidence) != 2 {
			t.Errorf("expected 2 evidence items in grouped finding, got %d", len(dbFindings[0].Evidence))
		}
	})
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

func TestM1Engine_GitRules_TrackedEnvTemplateDoesNotWarn(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "git",
				Evidence: []schema.Evidence{
					{Source: "git_tracked_env", Value: ".env.example, .env.production"},
					{Source: "git_env_exists", Value: "false"},
					{Source: "git_env_ignored", Value: "true"},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	for _, f := range findings {
		if f.ID == "F-GIT-001" && strings.Contains(f.Title, ".env.example") {
			t.Fatalf("tracked env template leaked into F-GIT-001 title: %s", f.Title)
		}
	}
	var hasRisky bool
	for _, f := range findings {
		if f.ID == "F-GIT-001" && strings.Contains(f.Title, ".env.production") {
			hasRisky = true
		}
	}
	if !hasRisky {
		t.Fatalf("expected risky tracked env file to still produce F-GIT-001, got: %v", findings)
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

func TestM1Engine_DiskRules_ZeroInodeStatsUnavailable(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "disk",
				Evidence: []schema.Evidence{
					{Source: "host_disk_free_bytes", Value: "10737418240"},
					{Source: "host_disk_free_pct", Value: "25.0"},
					{Source: "host_disk_total_inodes", Value: "0"},
					{Source: "host_disk_free_inodes", Value: "0"},
					{Source: "host_disk_free_inodes_pct", Value: "0.0"},
					{Source: "host_disk_inodes_available", Value: "false"},
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
			t.Errorf("unexpected F-DISK-001 when inode stats are unavailable, got: %v", findings)
		}
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

func TestM1Engine_SecurityRules_Denials(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "security",
				Evidence: []schema.Evidence{
					{Source: "selinux_denial", Value: "comm=node operation=read name=data.db class=file"},
					{Source: "apparmor_denial", Value: "profile=docker-default operation=open name=/workspace/config.json comm=python"},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	var hasSELinux, hasAppArmor bool
	for _, f := range findings {
		if f.ID == "F-SEC-SELINUX-001" {
			hasSELinux = true
		}
		if f.ID == "F-SEC-APPARMOR-001" {
			hasAppArmor = true
		}
	}
	if !hasSELinux || !hasAppArmor {
		t.Fatalf("expected SELinux and AppArmor findings, got: %v", findings)
	}
}

func TestM1Engine_SecurityRules_SELinuxContainerLabelGuidance(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "security",
				Evidence: []schema.Evidence{
					{Source: "selinux_denial", Value: "operation=write comm=node name=cache cwd=/workspace/current class=dir scontext=system_u:system_r:container_t:s0 tcontext=unconfined_u:object_r:default_t:s0 container_label_hint=mount_relabel_z_or_Z"},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	var got schema.Finding
	for _, f := range findings {
		if f.ID == "F-SEC-SELINUX-001" {
			got = f
			break
		}
	}
	if got.ID == "" {
		t.Fatalf("expected SELinux finding, got: %v", findings)
	}
	if !containsString(got.FixHints, "relabel-container-volume") {
		t.Fatalf("expected relabel-container-volume fix hint, got %v", got.FixHints)
	}
	if !containsString(got.LikelyCauses, "Container bind mount is missing an SELinux shared/private relabel such as :z or :Z") {
		t.Fatalf("missing container label likely cause: %v", got.LikelyCauses)
	}
}

func TestM1Engine_SecurityRules_AppArmorProfileGuidance(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "security",
				Evidence: []schema.Evidence{
					{Source: "apparmor_denial", Value: "profile=docker-default operation=open name=/workspace/current/config.json comm=python"},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	var got schema.Finding
	for _, f := range findings {
		if f.ID == "F-SEC-APPARMOR-001" {
			got = f
			break
		}
	}
	if got.ID == "" {
		t.Fatalf("expected AppArmor finding, got: %v", findings)
	}
	if !containsString(got.FixHints, "review-apparmor-profile") {
		t.Fatalf("expected review-apparmor-profile fix hint, got %v", got.FixHints)
	}
	if !containsString(got.LikelyCauses, "Docker default AppArmor profile denied access to the mounted project path") {
		t.Fatalf("missing docker-default AppArmor likely cause: %v", got.LikelyCauses)
	}
}

func TestM1Engine_HostRuntimeRules_RustRustc(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "runtime",
				Evidence: []schema.Evidence{
					{Source: "Cargo.toml", Value: "rust 1.75.0"},
				},
			},
			{
				Name: "host_runtime",
				Evidence: []schema.Evidence{
					{Source: "host_rustc_version", Value: "1.70.0"},
					{Source: "host_rustc_path", Value: "/usr/bin/rustc"},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	var hasRuntime006 bool
	for _, f := range findings {
		if f.ID == "F-RUNTIME-006" {
			hasRuntime006 = true
		}
	}
	if !hasRuntime006 {
		t.Errorf("expected F-RUNTIME-006 finding for rust/rustc mismatch, got: %v", findings)
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

func TestM1Engine_DockerRules_Unavailable(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name:   "docker",
				Status: schema.CollectorUnavailable,
				Evidence: []schema.Evidence{
					{Source: "docker_binary", Value: "/usr/bin/docker"},
				},
			},
		},
	}
	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	var hasDocker001 bool
	for _, f := range findings {
		if f.ID == "F-DOCKER-001" {
			hasDocker001 = true
		}
	}
	if !hasDocker001 {
		t.Errorf("expected F-DOCKER-001 finding, got: %v", findings)
	}
}

func TestM1Engine_DockerRules_SocketPermissionDenied(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name:   "docker",
				Status: schema.CollectorUnavailable,
				Evidence: []schema.Evidence{
					{Source: "docker_binary", Value: "/usr/bin/docker"},
					{Source: "docker_socket_permission_denied", Value: "true"},
				},
			},
		},
	}
	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	var hasDocker002 bool
	for _, f := range findings {
		if f.ID == "F-DOCKER-002" {
			hasDocker002 = true
		}
		if f.ID == "F-DOCKER-001" {
			t.Errorf("expected F-DOCKER-002, not F-DOCKER-001 when permission denied")
		}
	}
	if !hasDocker002 {
		t.Errorf("expected F-DOCKER-002 finding, got: %v", findings)
	}
}

func TestM1Engine_DockerRules_ComposePluginMissing(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name:   "docker",
				Status: schema.CollectorOK,
				Evidence: []schema.Evidence{
					{Source: "docker_binary", Value: "/usr/bin/docker"},
					{Source: "docker_compose_plugin", Value: "missing"},
				},
			},
			{
				Name:   "compose",
				Status: schema.CollectorOK,
				Evidence: []schema.Evidence{
					{Source: "compose", Value: "Compose config detected"},
				},
			},
		},
	}
	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	var hasDocker003 bool
	for _, f := range findings {
		if f.ID == "F-DOCKER-003" {
			hasDocker003 = true
		}
	}
	if !hasDocker003 {
		t.Errorf("expected F-DOCKER-003 finding, got: %v", findings)
	}
}

func TestM1Engine_DockerRules_NoComposeSignal_NoFinding(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name:   "docker",
				Status: schema.CollectorOK,
				Evidence: []schema.Evidence{
					{Source: "docker_binary", Value: "/usr/bin/docker"},
					{Source: "docker_compose_plugin", Value: "missing"},
				},
			},
		},
	}
	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	for _, f := range findings {
		if f.ID == "F-DOCKER-003" {
			t.Errorf("expected no F-DOCKER-003 when repo has no compose signals, got: %v", findings)
		}
	}
}

func TestM1Engine_PodmanRules_Unavailable(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name:   "podman",
				Status: schema.CollectorUnavailable,
				Evidence: []schema.Evidence{
					{Source: "podman_binary", Value: "not_found"},
				},
			},
		},
	}
	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	var hasPodman001 bool
	for _, f := range findings {
		if f.ID == "F-PODMAN-001" {
			hasPodman001 = true
		}
	}
	if !hasPodman001 {
		t.Errorf("expected F-PODMAN-001 finding, got: %v", findings)
	}
}

func TestM1Engine_PodmanRules_RuntimeDirGuidance(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name:   "podman",
				Status: schema.CollectorUnavailable,
				Evidence: []schema.Evidence{
					{Source: "podman_binary", Value: "present"},
					{Source: "podman_runtime_dir_error", Value: "true"},
				},
			},
		},
	}
	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	for _, f := range findings {
		if f.ID == "F-PODMAN-001" {
			if !containsString(f.LikelyCauses, "Rootless Podman runtime directory under /run/user is missing or inaccessible") {
				t.Fatalf("missing runtime-dir likely cause: %v", f.LikelyCauses)
			}
			return
		}
	}
	t.Fatalf("expected F-PODMAN-001 finding, got: %v", findings)
}

func TestM1Engine_ComposeStatusRules_ServiceNotRunning(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name:   "compose_status",
				Status: schema.CollectorOK,
				Evidence: []schema.Evidence{
					{Source: "compose_service_api_status", Value: "exited"},
				},
			},
		},
	}
	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	var hasContainer001 bool
	for _, f := range findings {
		if f.ID == "F-CONTAINER-001" {
			hasContainer001 = true
		}
	}
	if !hasContainer001 {
		t.Errorf("expected F-CONTAINER-001 finding, got: %v", findings)
	}
}

func TestM1Engine_ComposeStatusRules_ServiceUnhealthy(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name:   "compose_status",
				Status: schema.CollectorOK,
				Evidence: []schema.Evidence{
					{Source: "compose_service_db_health", Value: "unhealthy"},
				},
			},
		},
	}
	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	var hasContainer001 bool
	for _, f := range findings {
		if f.ID == "F-CONTAINER-001" {
			hasContainer001 = true
		}
	}
	if !hasContainer001 {
		t.Errorf("expected F-CONTAINER-001 finding, got: %v", findings)
	}
}

func TestM1Engine_ComposeStatusRules_BindMountMissing(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name:   "compose_status",
				Status: schema.CollectorOK,
				Evidence: []schema.Evidence{
					{Source: "compose_service_api_bind_mount_source", Value: "/host/data=false"},
				},
			},
		},
	}
	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	var hasContainer003 bool
	for _, f := range findings {
		if f.ID == "F-CONTAINER-003" {
			hasContainer003 = true
		}
	}
	if !hasContainer003 {
		t.Errorf("expected F-CONTAINER-003 finding, got: %v", findings)
	}
}

func TestM1Engine_ReproRules_NonZeroExit(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name:   "repro",
				Status: schema.CollectorOK,
				Evidence: []schema.Evidence{
					{Source: "repro_exit_code", Value: "1"},
				},
			},
		},
	}
	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	var hasRepro001 bool
	for _, f := range findings {
		if f.ID == "F-REPRO-001" {
			hasRepro001 = true
		}
	}
	if !hasRepro001 {
		t.Errorf("expected F-REPRO-001 finding, got: %v", findings)
	}
}

func TestM1Engine_ReproRules_SpecificClassificationSuppressesGeneric(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name:   "repro",
				Status: schema.CollectorOK,
				Evidence: []schema.Evidence{
					{Source: "repro_exit_code", Value: "1"},
					{Source: "repro_classification", Value: "permission_denied"},
				},
			},
		},
	}
	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	var hasRepro001, hasRepro002 bool
	for _, f := range findings {
		if f.ID == "F-REPRO-001" {
			hasRepro001 = true
		}
		if f.ID == "F-REPRO-002" {
			hasRepro002 = true
		}
	}
	if hasRepro001 {
		t.Errorf("expected F-REPRO-001 suppressed when specific classification exists")
	}
	if !hasRepro002 {
		t.Errorf("expected F-REPRO-002 finding, got: %v", findings)
	}
}

func TestM1Engine_ReproRules_Timeout(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name:   "repro",
				Status: schema.CollectorTimeout,
				Evidence: []schema.Evidence{
					{Source: "repro_timed_out", Value: "true"},
				},
			},
		},
	}
	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	var hasRepro009 bool
	for _, f := range findings {
		if f.ID == "F-REPRO-009" {
			hasRepro009 = true
		}
	}
	if !hasRepro009 {
		t.Errorf("expected F-REPRO-009 finding for timeout, got: %v", findings)
	}
}

func TestM1Engine_ReproRules_AddressInUse(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name:   "repro",
				Status: schema.CollectorOK,
				Evidence: []schema.Evidence{
					{Source: "repro_exit_code", Value: "1"},
					{Source: "repro_classification", Value: "address_in_use"},
				},
			},
		},
	}
	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	var hasRepro004 bool
	for _, f := range findings {
		if f.ID == "F-REPRO-004" {
			hasRepro004 = true
		}
	}
	if !hasRepro004 {
		t.Errorf("expected F-REPRO-004 finding, got: %v", findings)
	}
}

func TestM1Engine_ReproRules_RuntimeVersionFailure(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name:   "repro",
				Status: schema.CollectorOK,
				Evidence: []schema.Evidence{
					{Source: "repro_exit_code", Value: "1"},
					{Source: "repro_classification", Value: "runtime_version_failure"},
				},
			},
		},
	}
	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	var hasRepro006 bool
	for _, f := range findings {
		if f.ID == "F-REPRO-006" {
			hasRepro006 = true
		}
	}
	if !hasRepro006 {
		t.Errorf("expected F-REPRO-006 finding, got: %v", findings)
	}
}

func TestNormalizeVersion_StripsPrefixes(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{">=22.0.0", "22.0.0"},
		{"<=18.0.0", "18.0.0"},
		{"~>3.2.1", "3.2.1"},
		{"^1.2.3", "1.2.3"},
		{">14", "14"},
		{"<20", "20"},
		{"v20.0.0", "20.0.0"},
		{"go1.23.4", "1.23.4"},
		{"lts/*", "*"},
		{"node", ""},
		{"  18.0.0  ", "18.0.0"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeVersion(tt.input)
			if got != tt.want {
				t.Errorf("normalizeVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestVersionsCompatible_WithPrefix(t *testing.T) {
	// .nvmrc containing >=22 should not mismatch with host node 22.11.1
	if !versionsCompatible(">=22", "22.11.1") {
		t.Error("expected >=22 to be compatible with 22.11.1")
	}
	if !versionsCompatible("<=18", "18.20.0") {
		t.Error("expected <=18 to be compatible with 18.20.0")
	}
	if !versionsCompatible("lts/*", "20.0.0") {
		t.Error("expected lts/* to be compatible with any version")
	}
	// Pinned versions still require exact major.minor match
	if versionsCompatible("18.0.0", "18.20.0") {
		t.Error("expected 18.0.0 to NOT be compatible with 18.20.0")
	}
}

func TestVersionsCompatible_SemverRanges(t *testing.T) {
	tests := []struct {
		expected string
		actual   string
		want     bool
	}{
		{">=20 <23", "22.11.1", true},
		{">=20 <23", "23.0.0", false},
		{"^20.1.0", "20.4.0", true},
		{"^20.1.0", "21.0.0", false},
		{"~20.1.0", "20.1.9", true},
		{"~20.1.0", "20.2.0", false},
	}

	for _, tt := range tests {
		t.Run(tt.expected+"_"+tt.actual, func(t *testing.T) {
			got := versionsCompatible(tt.expected, tt.actual)
			if got != tt.want {
				t.Fatalf("versionsCompatible(%q, %q) = %v, want %v", tt.expected, tt.actual, got, tt.want)
			}
		})
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestEnvConfigIgnoresOptionalMissingKeys(t *testing.T) {
	engine := NewM1Engine()
	snapshot := graph.NormalizedSnapshot{
		Collectors: []schema.CollectorResult{
			{
				Name: "config",
				Evidence: []schema.Evidence{
					{Source: "devdiag_env_ignore_missing", Value: "NEXUQ_POSTGRES_PASSWORD"},
					{Source: "devdiag_env_optional", Value: "NEXUQ_WEBHOOK_SECRET"},
					{Source: "devdiag_env_required", Value: "NEXUQ_REQUIRED_PORT"},
				},
			},
			{
				Name: "env",
				Evidence: []schema.Evidence{
					{Source: "missing_keys", Value: "NEXUQ_POSTGRES_PASSWORD, NEXUQ_WEBHOOK_SECRET, NEXUQ_REQUIRED_PORT, NEXUQ_OTHER_PORT"},
				},
			},
		},
	}

	findings, err := engine.Evaluate(snapshot)
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}

	var hasMedium, hasInfo bool
	for _, f := range findings {
		if f.ID == "F-ENV-001" {
			if f.Severity == schema.SeverityMedium {
				hasMedium = true
				if strings.Contains(f.Title, "NEXUQ_POSTGRES_PASSWORD") {
					t.Error("NEXUQ_POSTGRES_PASSWORD should be ignored")
				}
				if !strings.Contains(f.Title, "NEXUQ_REQUIRED_PORT") {
					t.Error("expected NEXUQ_REQUIRED_PORT in medium severity finding")
				}
			} else if f.Severity == schema.SeverityInfo {
				hasInfo = true
				if !strings.Contains(f.Title, "NEXUQ_WEBHOOK_SECRET") {
					t.Error("expected NEXUQ_WEBHOOK_SECRET in optional/info severity finding")
				}
				if !strings.Contains(f.Title, "NEXUQ_OTHER_PORT") {
					t.Error("expected NEXUQ_OTHER_PORT in optional/info severity finding")
				}
			}
		}
	}

	if !hasMedium {
		t.Error("expected medium severity F-ENV-001 finding")
	}
	if !hasInfo {
		t.Error("expected info severity F-ENV-001 finding for optional keys")
	}
}
