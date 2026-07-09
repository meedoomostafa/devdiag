package fix

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Template is a registered fix template.
type Template struct {
	HintID           string
	Title            string
	Class            schema.FixClass
	Bin              string
	Args             []string // may contain placeholders like {{path}}, {{port}}, {{service}}, {{key}}
	Rollback         []string
	RequiredEvidence []string
	Platforms        []string // empty = all platforms
	ConfirmMessage   string
	BlockedReason    string
}

// Registry maps hint IDs to templates.
type Registry struct {
	templates map[string]Template
}

// NewRegistry creates a populated fix registry.
func NewRegistry() *Registry {
	r := &Registry{templates: make(map[string]Template)}
	r.registerDefaults()
	return r
}

// Lookup returns the template for a hint ID, or false if not found.
func (r *Registry) Lookup(hintID string) (Template, bool) {
	t, ok := r.templates[hintID]
	return t, ok
}

// List returns all registered templates.
func (r *Registry) List() []Template {
	var out []Template
	for _, t := range r.templates {
		out = append(out, t)
	}
	return out
}

// IsApplicable checks platform constraints.
func (t Template) IsApplicable() bool {
	if len(t.Platforms) == 0 {
		return true
	}
	goos := runtime.GOOS
	for _, p := range t.Platforms {
		if strings.EqualFold(p, goos) {
			return true
		}
	}
	return false
}

func (r *Registry) registerDefaults() {
	// M5 executable safe fixes
	r.register(Template{
		HintID:           "chmod-script",
		Title:            "Make script executable",
		Class:            schema.FixSafe,
		Bin:              "chmod",
		Args:             []string{"+x", "{{path}}"},
		Rollback:         []string{"chmod", "-x", "{{path}}"},
		RequiredEvidence: []string{"host_script_not_executable"},
		Platforms:        []string{"linux", "darwin"},
	})

	r.register(Template{
		HintID:           "gitignore-env",
		Title:            "Add .env to .gitignore",
		Class:            schema.FixManual,
		Args:             []string{"# Add '.env' to .gitignore: echo '.env' >> .gitignore"},
		RequiredEvidence: []string{"git_tracked_env", "git_env_exists"},
		Platforms:        []string{"linux", "darwin", "windows"},
	})

	// M5 manual/guarded proposals
	r.register(Template{
		HintID:           "change-compose-port",
		Title:            "Change Compose service port binding",
		Class:            schema.FixManual,
		Args:             []string{"# Edit compose.yaml and change the host port from {{port}} to an available port"},
		RequiredEvidence: []string{"compose_host_port", "host_listen_port"},
		Platforms:        []string{"linux", "darwin", "windows"},
	})

	r.register(Template{
		HintID:           "stop-service",
		Title:            "Stop the conflicting host service",
		Class:            schema.FixManual,
		Args:             []string{"# Find the service on port {{port}} and stop it: sudo ss -tlnp | grep :{{port}}"},
		RequiredEvidence: []string{"host_listen_port"},
		Platforms:        []string{"linux"},
	})

	r.register(Template{
		HintID:         "systemctl-daemon-reload",
		Title:          "Reload systemd manager configuration",
		Class:          schema.FixGuarded,
		Bin:            "systemctl",
		Args:           []string{"daemon-reload"},
		Platforms:      []string{"linux"},
		ConfirmMessage: "Reloads systemd manager configuration on this host. Use only after reviewing changed unit files.",
	})

	r.register(Template{
		HintID:           "suggest-docker-group",
		Title:            "Add user to docker group",
		Class:            schema.FixManual,
		Args:             []string{"# Run: sudo usermod -aG docker $USER && newgrp docker"},
		RequiredEvidence: []string{"docker_socket_permission_denied"},
		Platforms:        []string{"linux"},
	})

	r.register(Template{
		HintID:           "compose-up",
		Title:            "Start compose service",
		Class:            schema.FixGuarded,
		Bin:              "docker",
		Args:             []string{"compose", "--project-directory", "{{repo_root}}", "up", "-d", "{{service}}"},
		Rollback:         []string{"docker", "compose", "--project-directory", "{{repo_root}}", "stop", "{{service}}"},
		RequiredEvidence: []string{"compose_status"},
		Platforms:        []string{"linux", "darwin", "windows"},
		ConfirmMessage:   "Starts a Docker Compose service and may create or restart containers. Review the service logs and rollback command first.",
	})

	r.register(Template{
		HintID:    "inspect-service",
		Title:     "Inspect compose service logs",
		Class:     schema.FixManual,
		Args:      []string{"# View logs: docker compose logs --tail=200"},
		Platforms: []string{"linux", "darwin", "windows"},
	})

	r.register(Template{
		HintID:           "add-env-placeholder",
		Title:            "Add missing env keys as placeholders",
		Class:            schema.FixManual,
		Args:             []string{"# Create .env and add placeholders for the missing keys"},
		RequiredEvidence: []string{"missing_keys"},
		Platforms:        []string{"linux", "darwin", "windows"},
	})

	r.register(Template{
		HintID:           "warn-disk-cleanup",
		Title:            "Clean up disk or inode usage",
		Class:            schema.FixManual,
		Args:             []string{"# Consider: docker system prune -f, npm cache clean --force, or remove node_modules/.cache"},
		RequiredEvidence: []string{"host_disk_free_bytes", "host_disk_free_pct"},
		Platforms:        []string{"linux", "darwin", "windows"},
	})

	// M6 manual fix templates
	r.register(Template{
		HintID:    "install-nvidia-driver",
		Title:     "Install or reinstall NVIDIA driver",
		Class:     schema.FixManual,
		Args:      []string{"# Follow NVIDIA documentation for your distribution to install the correct driver"},
		Platforms: []string{"linux"},
	})

	r.register(Template{
		HintID:    "check-nvidia-driver",
		Title:     "Check NVIDIA driver and GPU visibility",
		Class:     schema.FixManual,
		Args:      []string{"# Verify driver state: nvidia-smi; check kernel module: lsmod | grep nvidia; review dmesg for NVRM errors"},
		Platforms: []string{"linux"},
	})

	r.register(Template{
		HintID:    "install-cuda-toolkit",
		Title:     "Install CUDA toolkit",
		Class:     schema.FixManual,
		Args:      []string{"# Install CUDA toolkit via distribution package manager or NVIDIA installer"},
		Platforms: []string{"linux"},
	})

	r.register(Template{
		HintID:    "install-pytorch-cuda",
		Title:     "Install PyTorch with CUDA support",
		Class:     schema.FixManual,
		Args:      []string{"# Visit https://pytorch.org/get-started/locally/ for the correct CUDA wheel"},
		Platforms: []string{"linux", "darwin", "windows"},
	})

	r.register(Template{
		HintID:    "install-tensorflow-gpu",
		Title:     "Install TensorFlow with GPU support",
		Class:     schema.FixManual,
		Args:      []string{"# Follow https://www.tensorflow.org/install/gpu for platform-specific instructions"},
		Platforms: []string{"linux", "darwin", "windows"},
	})

	r.register(Template{
		HintID:    "install-jax-cuda",
		Title:     "Install JAX with CUDA support",
		Class:     schema.FixManual,
		Args:      []string{"# Follow https://github.com/google/jax#pip-installation-gpu-cuda for CUDA-enabled JAX"},
		Platforms: []string{"linux", "darwin", "windows"},
	})

	r.register(Template{
		HintID:    "install-nvidia-toolkit",
		Title:     "Install NVIDIA Container Toolkit",
		Class:     schema.FixManual,
		Args:      []string{"# Follow https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html"},
		Platforms: []string{"linux"},
	})

	r.register(Template{
		HintID:    "fix-cache-permissions",
		Title:     "Fix cache directory permissions",
		Class:     schema.FixManual,
		Args:      []string{"# Run: sudo chown $USER:$USER <cache-path> (replace <cache-path> with the exact path from the finding)"},
		Platforms: []string{"linux", "darwin"},
	})

	r.register(Template{
		HintID:    "warn-docker-cleanup",
		Title:     "Clean up Docker build cache and unused images",
		Class:     schema.FixManual,
		Args:      []string{"# Run: docker system prune -f  (review what will be removed before confirming)"},
		Platforms: []string{"linux", "darwin", "windows"},
	})

	r.register(Template{
		HintID:    "disable-secure-boot-or-sign-module",
		Title:     "Disable Secure Boot or sign NVIDIA kernel module",
		Class:     schema.FixManual,
		Args:      []string{"# Prefer signing the module over disabling Secure Boot. See distribution docs for module signing."},
		Platforms: []string{"linux"},
	})

	// M7 Trace fixes
	r.register(Template{
		HintID:         "check-wd",
		Title:          "Verify working directory",
		Class:          schema.FixManual,
		ConfirmMessage: "Check that the process is running from the expected working directory.",
	})

	r.register(Template{
		HintID:         "verify-config-path",
		Title:          "Verify config file path",
		Class:          schema.FixManual,
		ConfirmMessage: "Ensure config files referenced by the process exist at the expected paths.",
	})

	r.register(Template{
		HintID:         "check-parent-permissions",
		Title:          "Check parent directory permissions",
		Class:          schema.FixManual,
		ConfirmMessage: "Verify that parent directories allow access for the current user.",
	})

	r.register(Template{
		HintID:         "check-file-owner",
		Title:          "Check file ownership",
		Class:          schema.FixManual,
		ConfirmMessage: "Verify that the file is owned by the expected user or group.",
	})

	r.register(Template{
		HintID:         "start-service",
		Title:          "Start the required service",
		Class:          schema.FixManual,
		ConfirmMessage: "Start the service the process is trying to connect to.",
	})

	r.register(Template{
		HintID:         "verify-port",
		Title:          "Verify port and host",
		Class:          schema.FixManual,
		ConfirmMessage: "Check that the process is connecting to the correct host and port.",
	})

	r.register(Template{
		HintID:         "verify-service-listening",
		Title:          "Verify service is listening",
		Class:          schema.FixManual,
		ConfirmMessage: "Check that the target service is actually listening on the expected address.",
	})

	r.register(Template{
		HintID:         "verify-unix-socket",
		Title:          "Verify UNIX socket path",
		Class:          schema.FixManual,
		ConfirmMessage: "Check that the UNIX socket file exists and has correct permissions.",
	})

	r.register(Template{
		HintID:           "ebpf-setcap-grant",
		Title:            "Grant permanent eBPF capabilities to devdiag binary",
		Class:            schema.FixGuarded, 
		Bin:              "sudo",
		Args:             []string{"setcap", "cap_bpf,cap_perfmon=ep", "{{value}}"},
		RequiredEvidence: []string{"trace_self_binary_path"}, 
		Platforms:        []string{"linux"},
		ConfirmMessage:   "This will elevate devdiag's binary permissions via setcap to allow raw tracepoint access for unprivileged users.",
	})
}

func (r *Registry) register(t Template) {
	if r.templates == nil {
		r.templates = make(map[string]Template)
	}
	// Primary safety gate: refuse to register blocked commands
	if isBlockedTemplate(t) {
		t.Class = schema.FixBlocked
		if t.BlockedReason == "" {
			t.BlockedReason = "command matches blocklist"
		}
	}
	r.templates[t.HintID] = t
}

// isBlockedTemplate checks if a template matches dangerous patterns.
func isBlockedTemplate(t Template) bool {
	// Check binary against blocklist
	if isBlockedBin(t.Bin) {
		return true
	}
	// Check each arg for dangerous patterns
	for _, a := range t.Args {
		if isBlockedArg(a) {
			return true
		}
	}
	for _, a := range t.Rollback {
		if isBlockedArg(a) {
			return true
		}
	}
	return false
}

func isBlockedBin(bin string) bool {
	b := filepath.Base(bin)
	switch b {
	case "rm", "rmdir", "chown", "setenforce", "sestatus", "mkfs", "fdisk", "dd":
		return true
	}
	return false
}

func isBlockedArg(arg string) bool {
	// Broad destructive patterns
	dangerous := []string{
		"rm -rf", "rm -fr", "rm -r -f",
		"rmdir -p",
		"chown -R /", "chown -R ~", "chown -R $HOME",
		"setenforce 0",
		"mkfs", "fdisk", "dd if=",
	}
	for _, d := range dangerous {
		if strings.Contains(arg, d) {
			return true
		}
	}
	// Volume deletion patterns
	if strings.Contains(arg, "docker volume rm") || strings.Contains(arg, "podman volume rm") {
		return true
	}
	// Remote host mutation
	if strings.Contains(arg, "ssh") && strings.Contains(arg, "rm") {
		return true
	}
	return false
}

// BindTemplate binds validated evidence values into a template's args and rollback.
func BindTemplate(t Template, values map[string]string) ([]string, []string, error) {
	boundArgs := make([]string, len(t.Args))
	copy(boundArgs, t.Args)
	boundRollback := make([]string, len(t.Rollback))
	copy(boundRollback, t.Rollback)

	for k, v := range values {
		placeholder := fmt.Sprintf("{{%s}}", k)
		for i := range boundArgs {
			boundArgs[i] = strings.ReplaceAll(boundArgs[i], placeholder, v)
		}
		for i := range boundRollback {
			boundRollback[i] = strings.ReplaceAll(boundRollback[i], placeholder, v)
		}
	}

	// Verify no remaining placeholders
	for _, a := range boundArgs {
		if strings.Contains(a, "{{") {
			return nil, nil, fmt.Errorf("unbound placeholder in args: %s", a)
		}
	}
	for _, r := range boundRollback {
		if strings.Contains(r, "{{") {
			return nil, nil, fmt.Errorf("unbound placeholder in rollback: %s", r)
		}
	}

	return boundArgs, boundRollback, nil
}
