# DevDiag — Full Comprehensive Product and Implementation Plan

> **Merged source:** This document preserves the complete comprehensive product plan and integrates the implementation-contract validation notes as a dedicated hard-requirements section. No source detail was intentionally removed.

## 0. Product Decision

**Product name:** DevDiag

**Positioning:** Linux-first, evidence-driven diagnostic CLI for developers.

**Core promise:**

> Run one command in a repo and get a ranked, evidence-backed explanation of why this project does not run correctly on this Linux machine, plus safe remediation steps.

**What this plan merges:**

- Research 1: DevDiag as a Linux-first repo-aware diagnostic engine that compares project expectations against host/container/runtime/security/kernel reality.
- Research 2: broader Linux developer bottlenecks: remote environment disconnect, Git mistakes, CI/CD fragility, agentic AI risks, HPC/GPU requirements, and developer workflow fragmentation.

**Explicitly excluded:**

- Artifact Capture / screenshot / ShareX-like daemon.
- GUI-first product.
- Always-on observability agent.
- Automatic destructive fixing.

---

## 1. Why This Product Should Exist

Linux developers do not usually lose time because they cannot write code. They lose time because their local environment, containers, runtime versions, shells, services, DNS, permissions, GPU stack, and CI expectations drift apart.

The typical failure is cross-layer:

```text
Project file looks correct
  ↓
Shell selects wrong runtime
  ↓
Docker/Podman changes mount ownership
  ↓
SELinux/AppArmor blocks access
  ↓
Service fails silently
  ↓
Logs are noisy and not actionable
```

Existing tools solve slices:

- `.env` linters validate env files.
- Dev Containers define reproducible environments.
- Docker/Podman expose container state.
- Nix/devenv reduce environment drift.
- `strace`, `bpftrace`, BCC, Tracee expose low-level evidence.
- Atuin helps with shell history.
- `act` helps emulate GitHub Actions locally.

But there is no dominant tool that joins all of these into one developer-facing diagnosis.

**DevDiag fills the gap by joining evidence across layers.**

### 1.1 Internet Keyword Coverage Audit

Current market and documentation signals confirm that DevDiag should deliberately cover these searchable problem clusters:

- **Local development environment troubleshooting:** "works on my machine", environment drift, developer environment diagnostics, reproducible dev environments, project bootstrap failure.
- **Docker Compose and Dev Containers:** Docker Compose environment variable precedence, Compose `develop`/watch workflows, service containers, `devcontainer.json`, bind mounts, health checks, profiles, and local service parity.
- **Podman and rootless Linux containers:** Podman, rootless containers, Podman Compose, user namespace UID/GID mapping, SELinux labels, AppArmor profiles, and Docker-to-Podman drift.
- **Nix-family and shell environment tools:** Nix, devenv, Devbox, direnv, `mise`, `asdf`, `pyenv`, `nvm`, `fnm`, SDKMAN, and version-manager shims.
- **CI/local parity:** GitHub Actions local execution, `act`, `wrkflw`, runner image drift, matrix runtime drift, secrets unavailable locally, and Docker-backed local CI simulation.
- **Service readiness and orchestration:** port conflicts, DNS/proxy/VPN drift, service readiness, Testcontainers-style dependency startup, `wait-for` tools, and host-to-container networking.
- **GPU/AI developer diagnostics:** CUDA, NVIDIA driver, `nvidia-smi`, NVIDIA Container Toolkit, PyTorch, TensorFlow, JAX, CPU-only wheels, container GPU visibility, and cache ownership for ML stacks.
- **Deep Linux evidence:** `strace`, syscall tracing, seccomp-bpf, eBPF, BTF/CO-RE, ptrace permissions, trace redaction, and opt-in overhead controls.
- **Policy, safety, and sharing:** current Go rule engines for milestone delivery, future OPA/Rego and CUE hardening, JSON/NDJSON output, redaction, local-only support capsule, dry-run fixes, guarded fixes, prompt-injection resistance, and AI-agent sandboxing.

Sources checked in May 2026 include Docker Compose environment-variable and Compose Develop documentation, the Dev Container specification, Podman documentation, `act`/`wrkflw` local GitHub Actions projects, devenv and Devbox documentation, CUE documentation, OPA/Rego references, and the Linux `strace(1)` manual.

---

## 2. Product Scope

### 2.1 In Scope

DevDiag should cover:

1. Repo expectation parsing.
2. Host runtime diagnosis.
3. Docker/Podman/container diagnosis.
4. Env var and config diagnosis.
5. Port/network/DNS/proxy diagnosis.
6. systemd/service diagnosis.
7. Filesystem/permission/UID/GID diagnosis.
8. SELinux/AppArmor diagnosis.
9. Git state and Git safety diagnosis.
10. CI/local parity diagnosis.
11. GPU/CUDA/ML stack diagnosis.
12. Optional command reproduction.
13. Optional `strace`-based evidence.
14. Optional eBPF-based evidence later.
15. Remote environment sync later.
16. Agentic CI/CD interceptor later.
17. Local AI explanation later.
18. Redacted support capsules.
19. Safe fix plans.

### 2.2 Out of Scope for Now

Do not build these in MVP:

1. Screenshot capture.
2. Screen recording.
3. ShareX-like GUI daemon.
4. Full remote IDE.
5. Always-on background monitoring.
6. Full observability/SIEM platform.
7. Automatic system-wide repair without review.
8. Replacing Docker, Podman, Dev Containers, Nix, or CI systems.

---

## 3. Target Users

### 3.1 Primary User

Linux developer working with:

- Docker or Podman.
- Node/Python/.NET/Go/Rust projects.
- Dev Containers.
- Local Postgres/Redis/RabbitMQ/etc.
- systemd services.
- Shell-managed runtimes like `nvm`, `pyenv`, `asdf`, `mise`.

### 3.2 Secondary User

DevOps / platform engineer supporting teams that frequently hit:

- “Works on my machine.”
- “Works in CI but not locally.”
- “Works locally but not in devcontainer.”
- “Works on Docker but not Podman.”
- “Works on X11 but not Wayland.”
- “GPU works in one shell but not in app/container.”

### 3.3 Later User

AI-agent-heavy developer who wants:

- Failing-command analysis.
- Safe patch suggestions.
- Prompt-injection guardrails.
- Local sandbox validation.
- Structured evidence for coding agents.

---

## 4. Product Thesis

DevDiag is not another linter.

DevDiag is a **diagnostic graph builder**.

It reads:

```text
Repo metadata
Host state
Shell state
Runtime state
Container state
Network state
Security policy state
Service state
GPU state
Git state
CI metadata
Command logs
Optional syscall/eBPF traces
```

Then it builds findings:

```text
Symptom → Evidence → Likely root cause → Confidence → Safe fix plan
```

The product should always answer:

1. What failed?
2. Why is that likely?
3. What evidence proves it?
4. What should I try first?
5. What is dangerous and should not be automated?
6. What exact data can I share safely with a teammate?

---

## 5. High-Level Architecture

```text
                      ┌──────────────────────┐
                      │      Repo Parser      │
                      │ package.json, .env,   │
                      │ Dockerfile, compose,  │
                      │ devcontainer, CI, etc │
                      └──────────┬───────────┘
                                 │
┌──────────────────────┐         │         ┌──────────────────────┐
│    Host Collector     │         │         │  Container Collector  │
│ distro, kernel, PATH, │         │         │ Docker, Podman, logs, │
│ shell, disk, services │         │         │ mounts, networks      │
└──────────┬───────────┘         │         └──────────┬───────────┘
           │                     │                    │
           └──────────────┬──────┴──────┬─────────────┘
                          │             │
                  ┌───────▼─────────────▼───────┐
                  │  Concurrent Collection Layer │
                  │ fan-out/fan-in, timeouts,    │
                  │ partial-result tolerance     │
                  └──────────────┬──────────────┘
                                 │
                  ┌──────────────▼──────────────┐
                  │      Diagnostic Graph        │
                  │ entities, relationships,     │
                  │ evidence, timestamps         │
                  └──────────────┬──────────────┘
                                 │
                         ┌───────▼───────┐
                         │ Policy Engine  │
                         │ Go now;        │
                         │ OPA/CUE later  │
                         │ deterministic  │
                         └───────┬───────┘
                                 │
              ┌──────────────────┼──────────────────┐
              │                  │                  │
      ┌───────▼───────┐  ┌───────▼───────┐  ┌───────▼───────┐
      │ Human Report   │  │ JSON/NDJSON    │  │ Fix Planner    │
      │ Markdown/CLI   │  │ machine output │  │ dry-run first  │
      └───────────────┘  └───────────────┘  └───────────────┘
                                 │
                         ┌───────▼───────┐
                         │ Redacted       │
                         │ Support Capsule│
                         └───────────────┘
```

### 5.1 Concurrency and Collection Performance Model

The collection layer must use a Fan-Out/Fan-In model.

Collectors must run concurrently where safe:

```text
repo parser
host collector
runtime collector
container collector
network collector
systemd collector
git collector
gpu collector
cache collector
```

Implementation requirements:

- Use Go goroutines for independent collectors.
- Use channels or `errgroup`-style coordination for fan-in.
- Every external command must run through `exec.CommandContext`.
- Every socket/API interaction must receive a context with timeout.
- The graph builder must accept partial snapshots.
- A collector timeout is a finding/evidence gap, not a fatal application error.
- Collectors must publish structured status: `ok`, `partial`, `timeout`, `permission_denied`, `unavailable`, `failed`.

Timeout model:

```text
Global scan soft budget: 3–5 seconds for default scan
Cheap collectors: 200–500ms
Normal collectors: 500ms–2s
Potentially slow collectors: opt-in, verbose, or deep mode
Trace collectors: explicit command only
```

Do not hard-code `500ms` for every collector. Some commands such as `docker info`, `journalctl`, GPU checks, and package-manager queries can exceed 500ms on real systems. The default should be strict enough to keep the CLI fast, but configurable per collector.

Example collector result:

```json
{
  "collector": "docker",
  "status": "timeout",
  "timeout_ms": 1200,
  "partial": true,
  "evidence": [],
  "notes": ["Docker daemon did not respond before timeout"]
}
```

SLA rule:

```text
Default scan should prioritize fast, high-signal checks.
Deep checks must be opt-in.
A slow collector must never block the whole scan.
```


---

## 5A. Agent Implementation Contract Addendum

## Validation Status

The submitted notes are **valid** as an implementation-facing summary of the current DevDiag plan. They do not introduce a major architectural contradiction. They should be added to the plan as a dedicated **Agent Implementation Contract** so an AI coding agent has a compact, non-negotiable reference while implementing the system.

Important nuance:

- The notes are mostly a distilled contract from the plan, not a new set of requirements.
- The only required plan update is to make these constraints explicit and hard to miss.
- The MVP statement “No GPU deep” remains valid even though GPU/ML is Milestone 6. It means GPU is not in the first shipping MVP cut line.

---

## Agent Implementation Contract

### 1. Language and Runtime

DevDiag must be implemented as a Go-first CLI.

Required implementation choices:

```text
Language: Go
Collector concurrency: goroutines + channels or errgroup-style fan-in
External commands: cmdrunner.CommandRunner backed by exec.CommandContext
Current milestone policy engine: Go rule engines for M1, M6, and M8
Future policy-engine hardening: OPA/Rego
Current milestone schema validation: Go structs, JSON marshaling tests, and fixture tests
Future schema/config validation: CUE or JSON Schema, with CUE preferred for structured constraints
Primary output formats: human, json, ndjson, markdown
```

Rationale:

- Go supports single-binary distribution, which avoids Node/Python bootstrap failures.
- `cmdrunner.CommandRunner` keeps cancellation-aware `exec.CommandContext` behavior testable and consistent.
- The current Go rule engines are accepted for milestone delivery because they are deterministic, covered by tests, and avoid adding policy dependencies before the rule surface stabilizes.
- OPA/Rego remains the preferred future policy backend once rule-pack boundaries are ready.
- CUE remains the preferred future structured validation layer once schemas and external rule packs are versioned.

Implementation requirements:

- Do not shell out through `sh -c` unless explicitly needed.
- Prefer direct executable + argv invocation.
- If shell execution is necessary, quote/escape inputs deliberately and mark the collector as higher risk.
- Capture stdout/stderr separately.
- Apply timeout and cancellation to every command.
- Treat timeout as a collector status, not a process-wide crash.

---

### 2. Architecture Pattern

The architecture must follow this pipeline:

```text
Fan-Out/Fan-In Collectors
  ↓
Normalized Snapshot
  ↓
Diagnostic Graph
  ↓
Policy Engine: Go rule engines now; OPA/Rego later
  ↓
Findings
  ↓
Human/JSON/NDJSON/Markdown Output
  ↓
Fix Planner
  ↓
Redacted Capsule
```

Collectors must not write findings directly as final truth. They produce normalized evidence. Policies produce finding candidates. The finding aggregator ranks, deduplicates, and renders results.

---

### 3. Collector Timeout and Partial Failure Model

Collectors must be concurrent and timeout-bounded.

Default timing model:

```text
Global scan soft budget: 3–5s
Cheap collectors: 200–500ms
Normal collectors: 500ms–2s
Slow collectors: configurable, opt-in, verbose, or deep mode
Trace collectors: explicit command only
```

Structured collector statuses:

```text
ok
partial
timeout
permission_denied
unavailable
failed
```

Rules:

- A slow collector must never block the whole scan.
- A failed collector is an evidence gap, not a fatal error.
- The graph builder must accept partial data.
- Report partial data clearly in human and JSON output.
- Do not silently hide collector failures.

Example:

```json
{
  "collector": "docker",
  "status": "timeout",
  "timeout_ms": 1200,
  "partial": true,
  "evidence": [],
  "notes": ["Docker daemon did not respond before timeout"]
}
```

---

### 4. Finding Schema Contract

The finding schema must be versioned and stable from the first public release.

Required top-level fields:

```text
schema_version
devdiag_version
run_id
redaction_status
repo
host
collectors
findings[]
```

Required per-finding fields:

```text
id
title
severity
confidence
layers[]
symptom
evidence[]
likely_causes[]
fixes[]
redaction_status
```

Rules:

- Add fields without breaking old consumers.
- Do not rename public fields casually.
- Include stable IDs for findings.
- Keep machine output free from banners or human-only formatting.
- Every finding must be traceable back to evidence.

---

### 5. Fix Model Contract

Fix classes:

```text
safe
  Low-risk, reversible, no data loss expected.

guarded
  Useful but can affect running state; requires TTY confirmation.

manual
  Explained but not executed by DevDiag.

blocked
  Too risky; DevDiag refuses to execute.
```

Non-negotiable rules:

- Default is always `--dry-run`.
- No fix runs without explicit user action.
- Guarded fixes require confirmation in an interactive TTY.
- No LLM-generated command is executed directly.
- Every applied fix must write an audit entry.
- Every guarded fix should show rollback guidance when possible.

Blocked examples:

```bash
sudo rm -rf /var/lib/docker
sudo chown -R $USER:$USER /
sudo setenforce 0
```

---

### 6. Redaction and Capsule Contract

Redaction is always enabled by default.

Rules:

- Redact values, not keys.
- No upload by default.
- Capsule is local-only unless user explicitly shares it.
- `--redact off` must be explicit and noisy.
- Machine output must include `redaction_status`.
- Logs, traces, command args, env values, URLs, Git remotes, and registry credentials must pass through the redaction layer.

Capsule file:

```text
support.devdiag.tgz
```

Capsule minimum contents:

```text
manifest.json
report.md
findings.json
snapshot/*.json
logs/*.log
redaction/rules-applied.json
```

Optional contents:

```text
trace/*.ndjson
policy/*.json
```

---

### 7. Output and Logging Contract

Supported output modes:

```bash
--format human
--format json
--format ndjson
--format markdown
```

Redaction modes:

```bash
--redact default
--redact strict
--redact off
```

Rules:

- Primary output goes to `stdout`.
- Logs, progress, warnings, and errors go to `stderr`.
- JSON output must be valid JSON only.
- NDJSON output must emit one JSON object per line.
- Respect `NO_COLOR`.
- Respect `--no-color`.
- Disable color automatically when output is not a TTY unless `--color always` is set.
- Do not rely on color alone for meaning.
- Do not rely on Nerd Fonts, icons, ligatures, or special glyphs.

Severity labels:

```text
trace
debug
info
notice
warn
error
fatal
```

Finding severity labels:

```text
critical
high
medium
low
info
```

These are separate concepts. Runtime logs describe DevDiag execution. Findings describe user environment risk.

---

### 8. Exit Code Contract

```text
0  success: no blocking issues
1  findings exist: one or more high/critical findings
2  invalid user input
3  collector failed partially
4  permission denied for requested collector
5  unsafe operation refused
6  command reproduction failed
7  trace unavailable
8  internal error
```

Rules:

- Exit code behavior must be documented.
- CI mode may allow configurable severity threshold.
- Do not return internal error for expected environment problems.
- A user’s broken Docker daemon is a finding or collector status, not DevDiag internal failure.

---

### 9. MVP Cut Line

The first shippable MVP includes:

```text
scan
check env
check runtimes
check containers
check ports
check git
repro
markdown output
JSON output
redaction
basic capsule draft
```

Explicitly not in first MVP:

```text
eBPF
AI
GPU deep diagnostics
remote sync
editor extension
team dashboard
auto-apply fixes
```

GPU/ML is still Milestone 6, meaning it comes early after the MVP foundation, but not inside the first cut line.

---

### 10. Milestone Order Contract

```text
0  Skeleton and invariants
1  Repo static diagnosis
2  Host/runtime/services diagnosis
3  Docker/Podman diagnosis
4  Repro runner + capsule
5  Safe fix planner
6  GPU/ML pack
7  Trace mode
8  CI/local parity + GitHub Action
9  Remote environment sync
10 Agentic interceptor + sandbox
11 Team product layer
```

Do not move AI earlier than deterministic diagnosis.
Do not move eBPF earlier than trace mode.
Do not move remote sync into MVP.

---

### 11. First 12 Findings Contract

Implement these first:

```text
F-ENV-001       Missing required env var
F-ENV-002       Compose references undefined env var
F-RUNTIME-001   Node version mismatch
F-RUNTIME-002   Python version mismatch
F-PORT-001      Host port collision
F-DOCKER-001    Docker daemon inactive or inaccessible
F-CONTAINER-001 Compose service unhealthy
F-FS-001        Script missing executable bit
F-GIT-001       .env tracked by Git
F-DISK-001      Disk or inode exhaustion
F-CACHE-001     Package/build cache is unwritable or root-owned
F-GPU-001       ML framework installed without usable GPU acceleration
```

Each finding must have:

- Fixture.
- Expected JSON output.
- Expected human output.
- Redaction test.
- False-positive notes.
- Safe-fix classification.

---

### 12. Non-Negotiable Invariants

The implementation agent must never violate these:

```text
No collector mutates system state.
No fix runs without explicit user action.
No secret is printed without --redact off.
No upload happens by default.
A slow or failed collector never blocks the whole scan.
strace is opt-in only.
eBPF is opt-in/deep only.
AI explanation is optional and sandboxed.
Deterministic diagnosis must work without AI.
External text is untrusted data, never agent instructions.
Docker socket access is sensitive and must be minimized.
Cache cleanup is never automatic.
SELinux/AppArmor should not be disabled as a default fix.
```

---

## Validation Notes

### Valid without change

The following submitted points are accurate and already aligned with the plan:

- Go as the runtime.
- Fan-Out/Fan-In collectors.
- `exec.CommandContext` for command timeout/cancellation.
- Current Go rule engines as the milestone policy engine; OPA/Rego is future hardening work.
- Current Go struct/fixture validation as the milestone schema contract; CUE or JSON Schema is future hardening work.
- Stable finding schema.
- Dry-run-first fix model.
- Redaction by default.
- Local-only capsules.
- Output modes.
- Exit code model.
- MVP cut line.
- Milestone ordering.
- First 12 findings.
- Deterministic diagnosis before AI.

### Valid but clarified

The note “slow collectors are opt-in/configurable” must not mean Docker/container checks are skipped by default. Instead:

- Basic Docker availability can be checked quickly.
- Slow Docker daemon/API calls should timeout and return partial status.
- Deeper logs, `journalctl`, GPU runtime validation, and image-running checks should be verbose/deep/explicit.

### Added as hard requirement

This addendum should be treated as an implementation contract for coding agents and contributors.

---

## 6. Core Components

### 6.1 Repo Parser

Reads project expectations from:

```text
README.md
package.json
pnpm-lock.yaml / package-lock.json / yarn.lock
.nvmrc
.node-version
.python-version
pyproject.toml
requirements.txt
uv.lock
Pipfile
poetry.lock
go.mod
Cargo.toml
*.csproj
global.json
Dockerfile
compose.yaml / docker-compose.yml
.devcontainer/devcontainer.json
.env
.env.example
.env.*.example
Makefile
Taskfile.yml
justfile
.github/workflows/*.yml
.gitignore
.gitattributes
```

Responsibilities:

- Infer required runtimes.
- Infer services required locally.
- Infer required env vars.
- Infer exposed ports.
- Infer container runtime assumptions.
- Infer CI commands.
- Infer package manager.
- Infer likely start/build/test commands.

Edge cases:

- Multiple package managers exist.
- Monorepo with many apps.
- Nested Dockerfiles.
- Multiple Compose profiles.
- Generated lockfiles stale.
- README says one command, CI uses another.
- `.env.example` incomplete.
- Environment variables created dynamically in scripts.
- Framework conventions hide required env vars.

---

### 6.2 Host Collector

Captures host state without mutating it.

Collects:

```text
OS/distro/kernel
CPU/memory
Disk bytes and inodes
Shell type
PATH
Current working directory
Current user UID/GID/groups
Terminal type
Session type: X11/Wayland/headless
Runtime binaries and versions
systemd user/system services
DNS resolver state
Proxy environment variables
Firewall hints
SELinux/AppArmor status
GPU/NVIDIA/CUDA state
```

Commands/signals:

```bash
uname -a
cat /etc/os-release
id
groups
printenv
which node python dotnet go rustc cargo docker podman
node -v
python --version
dotnet --info
go version
rustc --version
df -h
df -i
ss -ltnp
resolvectl status
systemctl status <service>
journalctl -u <service>
getenforce
aa-status
nvidia-smi
nvcc --version
```

Edge cases:

- Command not installed.
- User lacks permissions.
- `sudo` changes PATH.
- Non-interactive shell differs from interactive shell.
- Fish shell path differs from Bash/Zsh.
- systemd unavailable in containers/WSL.
- `resolvectl` unavailable.
- `lsof` missing.
- BusyBox/Alpine variants.
- Immutable OS with read-only root.
- Corporate lockdown blocks inspection.

---

### 6.3 Container Collector

Supports Docker first, Podman second, then containerd/nerdctl later.

Collects:

```text
Runtime type and version
Daemon/rootless/rootful mode
Compose version
Containers and health
Images
Networks
Volumes
Port mappings
Mounts
Container logs
Resource limits
User namespace mode
SELinux labels
AppArmor profiles
```

Commands/signals:

```bash
docker info
docker ps -a
docker compose ps
docker compose config
docker compose logs --tail=200
docker system df
podman info
podman ps -a
podman compose ps
podman network ls
podman inspect <container>
```

Edge cases:

- Docker socket unavailable.
- User not in `docker` group.
- Docker rootless mode.
- Podman rootless UID/GID mapping.
- Compose plugin missing.
- Compose v1 vs v2 behavior.
- Docker context points to remote daemon.
- Podman machine on macOS/Windows later.
- Stale containers from old project path.
- Container name collisions.
- Healthcheck absent or misleading.
- Port mapped to IPv6 only.
- Bind mount hides image content.
- Volume contains stale database state.
- Build cache causes stale behavior.

---

### 6.4 Runtime Version Analyzer

Detects mismatch between project requirements and active versions.

Covers:

```text
Node: nvm, fnm, volta, mise, asdf
Python: pyenv, uv, poetry, venv, conda, system Python
.NET: global.json, SDK/runtime versions
Go: go.mod version/toolchain
Rust: rust-toolchain.toml, rustup
Java: SDKMAN/asdf/system Java
CUDA/PyTorch/TensorFlow/JAX compatibility
```

Findings examples:

```text
Project requires Node >=22 but current shell resolves node 20.11.1.
Poetry selected Python 3.10 but pyproject requires >=3.12.
global.json pins .NET SDK 10.0 but only 8.0 is installed.
Torch CUDA wheel expects CUDA 12.x but driver is too old.
```

Edge cases:

- Version manager installed but not initialized.
- Runtime works in shell but not in non-interactive task.
- `sudo` bypasses shims.
- IDE terminal loads different shell config.
- Container runtime uses different version than host.
- CI uses a third version.
- Lockfile generated with another runtime.
- System package shadows version-manager binary.

---

### 6.5 Env and Config Analyzer

Compares expected and actual env configuration.

Sources:

```text
.env
.env.example
.env.local
.env.development
Docker Compose env_file
Docker Compose environment
Shell env
CI env references
Framework-specific env usage
```

Checks:

- Missing required variables.
- Extra suspicious variables.
- Empty required variables.
- Duplicate keys.
- Conflicting values across shell and `.env`.
- Compose interpolation mismatch.
- Secrets accidentally committed.
- Quoting/escaping issues.
- Boolean/string coercion mistakes.
- Wrong env file loaded.

Edge cases:

- Env vars are intentionally loaded by secrets manager.
- `.env.example` incomplete.
- Values computed at runtime.
- App validates env internally but not documented.
- Multiline secrets.
- Variables with `=` inside value.
- Comments inside values.
- Docker Compose precedence differs from app expectations.

---

### 6.6 Network, DNS, Proxy, and Port Analyzer

Covers:

```text
Port conflicts
Wrong bind address
Unexpected public exposure
IPv4/IPv6 mismatch
Host-to-container DNS drift
Container-to-host resolution
Corporate proxy mismatch
VPN interference
Firewall hints
localhost confusion inside containers
```

Checks:

```bash
ss -ltnp
lsof -i :<port>
curl -v <url>
getent hosts <name>
resolvectl query <name>
docker compose config
inspect container /etc/resolv.conf
printenv | grep -i proxy
npm config get proxy
pip config debug
```

Findings examples:

```text
Port 5432 is already owned by host postgres.
Service binds to 127.0.0.1 inside container, so host cannot reach it.
Container cannot resolve internal hostname because custom DNS is not propagated.
Docker daemon proxy is configured but npm proxy is not.
```

Edge cases:

- Process info requires root.
- Port owned by another user.
- IPv6 socket appears to cover IPv4 depending on kernel config.
- Docker publishes on all interfaces by default.
- VPN overrides DNS.
- Split DNS with systemd-resolved.
- Corporate proxy requires auth.
- Proxy credentials must be redacted.
- `localhost` inside container means container, not host.
- Host gateway differs across Docker/Podman/rootless.

---

### 6.7 Filesystem, Permission, and Security Policy Analyzer

Covers:

```text
EACCES
ENOENT
EROFS
EPERM
Read-only mounts
Missing executable bit
Wrong ownership
UID/GID mismatch
SELinux labels
AppArmor denials
Immutable distro constraints
Disk/inode exhaustion
```

Checks:

```bash
stat <path>
ls -ld <path>
ls -Z <path>
id
mount
findmnt
df -h
df -i
getenforce
aa-status
dmesg | grep DENIED
journalctl -k
```

Findings examples:

```text
Script exists but is not executable.
Workspace mount owner does not match container user.
SELinux is enforcing and mount lacks :z or :Z label.
Root filesystem is read-only because OS is immutable.
Disk has free bytes but zero free inodes.
```

Edge cases:

- Permission denied caused by parent directory, not target file.
- ACLs override classic Unix mode bits.
- SELinux denies access even when Unix permissions look correct.
- AppArmor denial appears only in kernel logs.
- NFS/CIFS mounts behave differently.
- Files owned by root because previous command used sudo.
- Git checkout marks file executable differently across OS.
- Case-sensitive path mismatch.
- Symlink target missing.
- Bind mount hides expected image files.

---

### 6.8 systemd and Local Service Analyzer

Covers:

```text
Docker daemon
Podman socket
Postgres/Redis local services
User services
Failed units
Stale unit files
Wrong ExecStart
Missing env files
```

Checks:

```bash
systemctl status <unit>
systemctl --user status <unit>
systemctl cat <unit>
systemctl show <unit>
journalctl -u <unit> --no-pager -n 200
journalctl --user -u <unit> --no-pager -n 200
```

Findings examples:

```text
Unit was modified but systemd daemon was not reloaded.
Service failed because ExecStart points to missing binary.
User service cannot access env var defined only in interactive shell.
Docker daemon is inactive.
Podman socket is not enabled.
```

Edge cases:

- systemd unavailable.
- User service vs system service confusion.
- Unit has drop-in overrides.
- Service restarts too quickly and hits StartLimitBurst.
- EnvFile missing but logs are vague.
- Journal access denied.
- Service uses different working directory.
- Socket-activated service appears inactive until used.

---

### 6.9 Git Guardrails Analyzer

This is a merged idea from the broader research, but it should be a module, not a separate product at first.

Covers:

```text
Unresolved merge conflicts
Generated files tracked accidentally
Large files committed
Secrets committed
Missing .gitignore rules
Branch divergence
Detached HEAD confusion
Submodule drift
Git LFS missing
Protected branch risk
```

Commands/signals:

```bash
git status --porcelain=v1
git diff --name-only --diff-filter=U
git ls-files
git log --oneline --decorate -n 20
git branch -vv
git lfs status
```

Findings examples:

```text
Checkout is blocked because repository has unresolved merge conflicts.
Large binary file is staged and should probably use Git LFS.
.env file is tracked and contains likely secrets.
Local branch is ahead of origin but PR will not show missing files until push.
```

Edge cases:

- Monorepo with generated assets intentionally tracked.
- Vendor directories intentionally committed.
- LFS not installed locally.
- Submodules intentionally pinned.
- Secrets false positives.
- Binary file threshold differs by team policy.
- Worktrees.
- Sparse checkout.
- Shallow clone in CI.

---

### 6.10 CI/Local Parity Analyzer

Reads:

```text
.github/workflows/*.yml
.gitlab-ci.yml
Dockerfile
compose.yaml
.devcontainer/devcontainer.json
Makefile
Taskfile.yml
justfile
```

Checks:

- CI uses different runtime version than local.
- CI has env vars local does not.
- Local has service containers CI does not.
- Devcontainer differs from CI image.
- Build command differs from README.
- Matrix job hides failing platform.
- Cache key stale or invalid.
- CI uses Docker-in-Docker assumptions.

Findings examples:

```text
CI uses Node 22 but .nvmrc pins Node 20.
README says `npm run dev`, CI builds with `pnpm build`.
GitHub Actions service Postgres uses port 5432 but local compose maps 5433.
```

Edge cases:

- Reusable workflows.
- Composite actions.
- Matrix includes many versions.
- Secrets unavailable locally.
- CI-specific hosted runner tools.
- Docker layer cache not reproducible locally.
- `act` behavior differs from GitHub-hosted runners.

---

### 6.11 Cache Analyzer

Stale or corrupted caches are a major source of non-deterministic "works on my machine" failures. DevDiag should treat cache state as first-class evidence, not as an afterthought.

Targets:

```text
Docker BuildKit cache
Docker image/layer cache
Podman build cache
npm cache: ~/.npm/_cacache
pnpm store
yarn cache
Go build cache: go env GOCACHE
Go module cache: go env GOMODCACHE
Cargo cache and target directory
pip cache
uv cache
Poetry cache
.NET NuGet cache
Gradle/Maven caches later
```

Checks:

- Package manager cache exists but does not match active lockfile expectations.
- Cache belongs to root due to previous `sudo` install.
- Cache path is unreadable/unwritable.
- Docker/BuildKit cache is large or stale relative to repo state.
- Go build cache path differs between shell, CI, and container.
- Cache corruption hints in command stderr.
- Repeated failure disappears after cache bypass in controlled repro.

Commands/signals:

```bash
docker system df
docker buildx du
npm cache verify
go env GOCACHE GOMODCACHE
cargo metadata
pip cache dir
uv cache dir
poetry cache list
dotnet nuget locals all --list
```

Safety rules:

- Never clear caches automatically by default.
- Prefer verification over deletion.
- Provide `--dry-run` cleanup estimates when possible.
- Treat cache pruning as guarded or manual.
- Warn that cache deletion can slow future builds and remove reusable layers.

Findings examples:

```text
npm cache directory is owned by root, likely from a previous sudo npm command.
Go build cache is unwritable by the current user.
Docker BuildKit cache is consuming 38GB and may be hiding stale build behavior.
Lockfile changed but dependency cache was reused during failing repro.
```

Edge cases:

- Large caches are not necessarily bad.
- Cache timestamps can be misleading.
- Monorepos can intentionally share caches.
- CI caches may be restored from remote keys.
- Package managers use content-addressed stores where apparent staleness is normal.
- Deleting cache can mask the real root cause instead of solving it.
- Cache paths can contain secrets in private registry URLs.

---

### 6.12 GPU/CUDA/AI Stack Analyzer

Important because Linux is dominant for ML/HPC and local AI development.

Checks:

```text
NVIDIA driver version
CUDA toolkit version
cuDNN hints
PyTorch CUDA version
TensorFlow/JAX backend
GPU visibility inside containers
NVIDIA Container Toolkit
Compute capability hints
VRAM availability
MIG mode hints
```

Commands/signals:

```bash
nvidia-smi
nvcc --version
python -c "import torch; print(torch.__version__, torch.cuda.is_available(), torch.version.cuda)"
python -c "import tensorflow as tf; print(tf.config.list_physical_devices('GPU'))"
docker run --gpus all nvidia/cuda:... nvidia-smi
```

Findings examples:

```text
PyTorch is installed with CPU-only wheel.
CUDA wheel expects runtime unavailable on this host.
Container does not see GPU because NVIDIA Container Toolkit is missing.
Driver is too old for selected CUDA runtime.
```

Edge cases:

- WSL later.
- Multiple CUDA versions installed.
- `LD_LIBRARY_PATH` shadows expected libraries.
- Conda CUDA runtime differs from system CUDA.
- Container CUDA version differs from host driver support.
- MIG mode splits GPU memory unexpectedly.
- Nouveau driver conflict.
- Secure Boot blocks NVIDIA module.
- AMD ROCm support later.

---

### 6.13 Remote Environment Sync Module

This comes from the broader Linux workflow research. It should not be MVP core, but it is strategically valuable.

Problem:

Developers have optimized local shells, but remote servers, SSH sessions, containers, and Kubernetes pods are bare and hostile.

Goal:

Temporarily inject a safe, minimal, reversible developer environment into remote sessions.

Commands:

```bash
devdiag remote enter user@host
devdiag remote enter container:<id>
devdiag remote enter k8s:namespace/pod
devdiag remote sync --profile minimal
devdiag remote clean
```

What to sync:

```text
aliases
shell prompt minimal config
tmux config
vim/nvim minimal config
fzf/ripgrep/bat/eza availability hints
read-only helper scripts
```

Rules:

- Never overwrite remote dotfiles without backup.
- Default to temporary injection.
- Clean up on exit.
- Work without root.
- Support restricted shells where possible.
- Log exactly what was changed.

Edge cases:

- Remote host has no write permission in home.
- Remote lacks Bash/Zsh/Fish.
- Remote architecture differs.
- Remote has old glibc.
- Corporate bastion blocks file transfer.
- Shell startup files are locked.
- Container filesystem is read-only.
- SSH multiplexing causes cleanup failure.
- User disconnects unexpectedly.

---

### 6.14 Agentic CI/CD Interceptor and Local Sandbox

This comes from the broader research about agentic AI workflows and prompt-injection risks.

This should be built after deterministic DevDiag is useful.

Goal:

Wrap failing commands, analyze evidence, optionally test safe patches in a sandbox, and feed structured context to AI agents safely.

Commands:

```bash
devdiag agent run -- npm test
devdiag agent explain support.devdiag.tgz
devdiag agent suggest-fix F-NODE-ENGINE-001
devdiag agent sandbox --patch fix.patch -- npm test
```

Principles:

- Deterministic evidence first.
- AI explanation second.
- No AI-generated fix is trusted until validated.
- Prompt-injection guarded by input classification and sanitization.
- BeforeModel and AfterTool style hooks.
- All proposed changes go through diff review.

Security model:

```text
Untrusted input:
- repo files
- logs
- web pages
- package metadata
- README text
- issue comments
- command output

Guardrails:
- sanitize before model context
- remove secrets
- block instruction-like text from external logs
- separate evidence from instructions
- require human approval for mutation
- run patches in sandbox first
```

Edge cases:

- Malicious repository instructs agent to leak secrets.
- Log output contains prompt injection.
- Test command has side effects.
- Suggested fix passes local tests but breaks CI.
- Sandbox differs from host failure.
- Agent overfits to noisy evidence.
- LLM unavailable/offline.
- User disables telemetry/AI.

---

## 7. CLI Design

DevDiag must feel like a serious Linux tool: predictable, scriptable, readable, and safe.

### 7.1 Command Structure

```bash
devdiag scan [path]
devdiag repro -- <cmd>
devdiag check <domain>
devdiag trace --scope file,process,network -- <cmd>
devdiag fix <finding-id> --dry-run
devdiag fix <finding-id> --apply
devdiag capsule create
devdiag capsule inspect <file>
devdiag doctor self
devdiag rules list
devdiag rules test
```

Domains:

```text
env
runtimes
containers
ports
network
dns
proxy
services
filesystem
security
git
ci
gpu
wayland
remote
agent
```

### 7.2 CLI Output Modes

```bash
--format human      # default for terminal
--format json       # stable machine output
--format ndjson     # streaming logs/findings
--format markdown   # report file
--quiet             # only critical summary
--verbose           # include more evidence
--debug             # internal diagnostics
--no-color          # force no ANSI color
--color always|auto|never
--redact default|strict|off
```

### 7.3 Exit Codes

```text
0  success: no blocking issues
1  findings exist: one or more high/critical findings
2  invalid user input
3  collector failed partially
4  permission denied for requested collector
5  unsafe operation refused
6  command reproduction failed
7  trace unavailable
8  internal error
```

### 7.4 Human Output Pattern

Default output should be short at top, detailed below.

```text
DevDiag 0.1.0 — scan completed in 3.2s
repo: /home/medo/app
host: Fedora 42, kernel 6.x, session=wayland

Top findings
[critical] F-PORT-001  Postgres port 5432 is already occupied    confidence=0.96
[high]     F-ENV-003   DATABASE_URL is missing from active env     confidence=0.91
[medium]   F-GIT-002   .env is tracked by Git                      confidence=0.82

Suggested next command
  devdiag explain F-PORT-001

Machine output
  devdiag scan . --format json
```

Detailed finding:

```text
F-PORT-001  Postgres port 5432 is already occupied
Severity:   critical
Confidence: 0.96
Layers:     repo → docker-compose → host network

Symptom
  docker compose cannot start postgres because host port 5432 is already bound.

Evidence
  compose.yaml maps postgres: "5432:5432"
  ss -ltnp shows pid=1842 process=postgres listening on 127.0.0.1:5432
  compose stderr contains: bind: address already in use

Recommended fix
  Option A: stop the existing local postgres service
    sudo systemctl stop postgresql

  Option B: change host port in compose.yaml
    "5433:5432"

Safety
  No command will be applied automatically.
```

---

## 8. Font and Terminal Log Presentation Guidance

### 8.1 Important Constraint

A CLI usually does **not** control the user's terminal font. The user’s terminal emulator controls font rendering.

So DevDiag should be **font-agnostic**:

- Do not rely on icons that require Nerd Fonts.
- Do not rely on ligatures.
- Do not rely on box drawing for critical meaning.
- Do not rely only on color.
- Always support plain ASCII fallback.

### 8.2 Recommended Fonts for Demos and Documentation

For screenshots, docs, landing pages, demo GIFs, and examples, use one of:

1. **JetBrains Mono**
   - Strong developer familiarity.
   - Good readability.
   - Works well in terminals and code blocks.

2. **Iosevka**
   - Very compact.
   - Excellent for dense terminal output.
   - Good when showing long paths/logs.

3. **Fira Code**
   - Popular and readable.
   - Good for marketing material.
   - Avoid relying on ligatures for meaning.

Product recommendation:

```text
Docs/demo default: JetBrains Mono
Dense terminal report examples: Iosevka
Fallback: system monospace
```

### 8.3 Log and CLI Formatting Rules

Follow these rules:

1. Primary machine-readable output goes to `stdout`.
2. Human logs, progress, warnings, and errors go to `stderr`.
3. JSON output must be valid JSON with no extra banners.
4. NDJSON output must emit one JSON object per line.
5. ANSI color only when output is a TTY and color is enabled.
6. Respect `NO_COLOR`.
7. Respect `--no-color`.
8. Use severity labels consistently.
9. Avoid noisy repeated logs.
10. Keep top-level summary short.
11. Put exact evidence below the summary.
12. Never print secrets unless redaction is explicitly disabled.

### 8.4 Severity Levels

Use a small fixed severity model:

```text
trace   internal step-level diagnostics; hidden unless --debug
debug   developer debugging for DevDiag itself
info    normal progress or non-problem evidence
notice  useful non-blocking observation
warn    likely problem but not necessarily blocking
error   blocking finding for current command
fatal   DevDiag cannot continue
```

For user-facing findings, map to:

```text
critical
high
medium
low
info
```

Reason:

- Logging severity and finding severity are not the same thing.
- A log line describes DevDiag execution.
- A finding describes the user's environment risk.

### 8.5 Structured Log Format

Human stderr log:

```text
2026-05-16T12:10:02Z INF collector.start domain=containers runtime=docker
2026-05-16T12:10:02Z WRN collector.partial domain=systemd reason="journal access denied"
2026-05-16T12:10:03Z ERR finding.detected id=F-PORT-001 severity=critical confidence=0.96
```

NDJSON log:

```json
{"ts":"2026-05-16T12:10:02Z","level":"info","event":"collector.start","domain":"containers","runtime":"docker"}
{"ts":"2026-05-16T12:10:02Z","level":"warn","event":"collector.partial","domain":"systemd","reason":"journal access denied"}
{"ts":"2026-05-16T12:10:03Z","level":"error","event":"finding.detected","id":"F-PORT-001","severity":"critical","confidence":0.96}
```

### 8.6 Color Rules

Do not make color semantically required.

Suggested color mapping only:

```text
critical/error: red
high/warn: yellow
medium: magenta or yellow
low/info: blue or cyan
success: green
muted evidence: gray
```

Plain fallback:

```text
[critical]
[high]
[medium]
[low]
[info]
```

### 8.7 Progress Output

Good:

```text
scanning repo metadata... done
checking containers... partial: Docker socket denied
checking ports... found 1 conflict
building findings... 3 findings
```

Bad:

```text
DEBUG: running command 1
DEBUG: running command 2
DEBUG: running command 3
...
```

### 8.8 Machine Output Stability

Once `--format json` is public:

- Do not rename fields casually.
- Add fields instead of replacing.
- Version the schema.
- Include `schema_version`.
- Include `devdiag_version`.
- Include `run_id`.
- Include `redaction_status`.

---

## 9. Findings Model

Stable schema from the beginning:

```json
{
  "schema_version": "0.1",
  "devdiag_version": "0.1.0",
  "run_id": "2026-05-16T12:10:02Z_7c5f",
  "repo": {
    "root": "/workspace/app",
    "signals": ["compose.yaml", ".nvmrc", ".env.example"]
  },
  "host": {
    "os": "linux",
    "distro": "Fedora",
    "version": "42",
    "kernel": "6.x",
    "session": "wayland"
  },
  "findings": [
    {
      "id": "F-PORT-001",
      "title": "Postgres port 5432 is already occupied",
      "severity": "critical",
      "confidence": 0.96,
      "layers": ["repo", "compose", "network"],
      "symptom": "docker compose cannot bind host port 5432",
      "evidence": [
        {
          "source": "compose.yaml",
          "value": "5432:5432"
        },
        {
          "source": "ss",
          "value": "pid=1842 postgres listening on 127.0.0.1:5432"
        }
      ],
      "likely_causes": [
        "local postgres service already running"
      ],
      "fixes": [
        {
          "class": "guarded",
          "title": "stop local postgres service",
          "commands": ["sudo systemctl stop postgresql"],
          "rollback": ["sudo systemctl start postgresql"]
        }
      ],
      "redaction_status": "safe"
    }
  ]
}
```

---

## 10. Policy Engine Design

### 10.1 Decision

Do not build a complex custom YAML evaluation DSL.

A YAML DSL with nested `all`, `any`, `not`, `boost`, joins, graph traversal, and scoring will eventually become an unmaintainable pseudo-language. DevDiag should instead use a real policy/evaluation language and keep YAML only for metadata where appropriate.

Recommended approach:

```text
Current milestone policy engine: Go rule engines
Future policy engine: OPA/Rego
Current milestone schema/config validation: Go structs, JSON marshaling tests, and fixtures
Future schema/config validation: CUE or JSON Schema
Rule metadata: YAML or JSON only for labels, docs, severity defaults, and fix templates
```

Rationale:

- The current Go engines already cover M1, M6, and M8 findings with deterministic tests and are accepted for this milestone.
- Rego is designed for declarative policy over structured JSON-like data and remains the preferred future backend for external policy packs.
- OPA can evaluate collected state deterministically once normalized policy input boundaries are stable.
- CUE is strong for validating and constraining structured configuration and remains preferred for future external schema/config validation.
- Go integration exists for both OPA and CUE when that future hardening work starts.
- This avoids inventing a fragile in-house rule language.

### 10.2 Input Model

The policy engine receives a normalized JSON diagnostic graph:

```json
{
  "repo": {},
  "host": {},
  "runtimes": {},
  "containers": {},
  "network": {},
  "services": {},
  "filesystem": {},
  "security": {},
  "git": {},
  "ci": {},
  "gpu": {},
  "cache": {},
  "repro": {},
  "trace": {}
}
```

Future OPA/Rego policies must emit finding candidates, not mutate state. Current Go rule engines must keep the same non-mutating contract.

### 10.3 Future Rego Policy Shape

Example:

```rego
package devdiag.findings.port

findings contains finding if {
  service := input.repo.compose.services[_]
  mapping := service.ports[_]
  host_port := mapping.host
  listener := input.network.listeners[host_port]

  finding := {
    "id": "F-PORT-001",
    "title": sprintf("Host port %v is already occupied", [host_port]),
    "severity": "critical",
    "confidence": 0.90,
    "layers": ["repo", "compose", "network"],
    "evidence": [
      {"source": "compose", "value": mapping},
      {"source": "ss", "value": listener}
    ]
  }
}
```

### 10.4 What Stays in Go

Keep these in Go, not Rego:

```text
collector execution
timeout handling
normalization
redaction
confidence post-processing if it needs numeric calibration
fix execution
output rendering
capsule creation
trace parsing
heavy graph indexing
```

Reason: Rego should decide policy/findings from normalized state. It should not become the execution runtime.

### 10.5 CUE Usage

Future CUE or JSON Schema validation should cover:

- Validating collector output schemas.
- Validating rule-pack metadata.
- Validating config files.
- Defining constraints for policy inputs.

Do not use CUE as the only finding engine unless the rule set proves mostly schema/constraint oriented. For future cross-layer diagnostic policies, OPA/Rego remains the better default. For the current milestone, Go struct validation and fixture tests are the accepted schema contract.

### 10.6 Policy Quality Requirements

Every policy must have:

1. Required input schema.
2. Expected finding output.
3. False-positive notes.
4. Unit fixtures.
5. Redaction classification.
6. Safe-fix class.
7. Performance budget.

### 10.7 Determinism Rules

- Policies must be pure: no shell execution from policy.
- Policies must not call network.
- Policies must not depend on wall-clock except supplied input timestamps.
- Policy evaluation must be bounded.
- Policy bundles must be versioned.
- Policy result ordering must be stable.

---

## 11. Safe Fix Model

### 11.1 Fix Classes

```text
safe
  Reversible, low-risk, no data loss expected.

guarded
  Useful but can affect running state; requires confirmation.

manual
  DevDiag explains but does not execute.

blocked
  DevDiag refuses because risk is too high.
```

### 11.2 Examples

Safe:

```bash
systemctl daemon-reload
```

Guarded:

```bash
sudo systemctl stop postgresql
```

Manual:

```text
Edit compose.yaml and change host port 5432 to 5433.
```

Blocked:

```bash
sudo rm -rf /var/lib/docker
```

### 11.3 Fix Execution Rules

- Default is `--dry-run`.
- `--apply` requires explicit finding ID.
- Never apply multiple risky fixes by default.
- Print rollback when possible.
- Show exact commands before execution.
- Require TTY confirmation for guarded fixes.
- In CI, never apply fixes unless explicitly configured.
- Never execute LLM-generated commands directly.

---

## 12. Redaction and Privacy Model

DevDiag will touch sensitive data. Privacy must be core architecture, not an afterthought.

### 12.1 Sensitive Data Classes

```text
.env values
API keys
JWTs
OAuth tokens
database URLs
proxy credentials
registry credentials
SSH paths
usernames
home directory paths
container image names from private registries
Git remote URLs
journal logs
shell history
```

### 12.2 Redaction Rules

- Redact values, not keys, by default.
- Preserve structural usefulness.
- Hash stable identifiers where useful.
- Never upload automatically.
- Capsules are local files only by default.
- `--redact off` requires explicit flag and warning.

Example:

```text
DATABASE_URL=postgres://user:pass@localhost:5432/app
```

becomes:

```text
DATABASE_URL=postgres://<user>:<redacted>@localhost:5432/<db>
```

### 12.3 Capsule Format

```text
support.devdiag.tgz
├── manifest.json
├── report.md
├── findings.json
├── snapshot/
│   ├── repo.json
│   ├── host.json
│   ├── container.json
│   ├── services.json
│   └── gpu.json
├── logs/
│   ├── command.stdout.log
│   ├── command.stderr.log
│   ├── journal.selected.log
│   └── container.runtime.log
├── trace/
│   ├── exec.ndjson
│   ├── file.ndjson
│   └── net.ndjson
└── redaction/
    └── rules-applied.json
```

Edge cases:

- Secret split across multiple lines.
- Token embedded in URL.
- Base64-encoded secret.
- Secret appears in stack trace.
- Secret appears in command arguments.
- Secret appears in Docker image history.
- Secret appears in Git remote URL.
- Redaction destroys useful evidence.

---

## 13. Deep Tracing Strategy

### 13.1 Principle

Deep tracing is escalation, not baseline.

Default path:

```text
static checks → runtime collectors → command repro → strace → optional eBPF
```

### 13.2 `strace` First, With Strict Overhead Controls

Use `strace` because it gives direct evidence for:

```text
ENOENT missing files
EACCES permission denied
ECONNREFUSED refused connections
EADDRINUSE port conflicts
execve wrong binary
openat wrong path
connect wrong socket
```

However, `strace -f` can heavily slow dependency-resolution and build commands because ptrace introduces user/kernel context-switch overhead. Therefore trace mode must be controlled, scoped, and opt-in.

Command:

```bash
devdiag trace --scope file,process,network -- npm run dev
```

Preferred internal invocation:

```bash
strace -ff \
  --seccomp-bpf \
  -e trace=%file,%process,%network \
  -o trace.log \
  -- npm run dev
```

Important constraints:

- Do not trace all syscalls blindly.
- Use `-e trace=%file,%process,%network` or narrower sets.
- Use `--seccomp-bpf` when available to reduce stop frequency for non-traced syscalls.
- Treat `--seccomp-bpf` as best-effort, not guaranteed.
- Detect and report when seccomp-bpf setup fails or is unsupported.
- Use trace size limits.
- Use time limits.
- Summarize trace output; do not dump raw trace by default.
- Redact paths, args, and env-like values.

Nuance:

`--seccomp-bpf` is an `strace` feature, not a custom DevDiag kernel program. It attempts to make the kernel stop the tracee only for syscalls selected by the trace filter. If setup fails, `strace` can proceed with normal ptrace behavior, so DevDiag must surface that degradation.

Edge cases:

- `strace` not installed.
- `--seccomp-bpf` unsupported by installed `strace`.
- User lacks ptrace permission.
- Yama `ptrace_scope` blocks tracing.
- Existing seccomp filter prevents notification.
- SUID programs behave differently under tracing.
- Trace output huge.
- Multi-process logs noisy.
- Paths contain secrets.
- Command behavior changes under tracing.
- Heavy commands become too slow even with filters.

### 13.3 eBPF Later, With Portability Guards

Use eBPF later for:

- Lower-overhead event collection.
- File open tracking.
- Exec tracking.
- Network connect tracking.
- Container-aware tracing.

But eBPF should be optional because:

- Requires privileges/capabilities.
- Kernel support differs.
- BTF/CO-RE support differs.
- Security-sensitive.
- Harder to package and debug.

Portability guard requirements:

```text
Before loading any CO-RE eBPF object:
1. Check for /sys/kernel/btf/vmlinux.
2. Check required capabilities/permissions.
3. Check kernel feature compatibility.
4. Check whether running under WSL/custom/legacy kernel.
5. If unsupported, fallback to strace or collector-only mode.
```

Behavior:

- Missing BTF is not fatal.
- Missing permissions are not fatal.
- eBPF collector must return `unavailable` or `permission_denied`, not crash.
- No local Clang/LLVM compilation should be required in normal installation.
- If CO-RE is unavailable, do not attempt unsafe runtime compilation by default.
- eBPF mode must be explicit or part of `--deep`.

Example fallback:

```text
eBPF unavailable: /sys/kernel/btf/vmlinux not found.
Falling back to strace-compatible trace mode.
```

---

## 14. Edge Case Matrix

### 14.1 Linux Environment Edge Cases

| Area | Edge case | Required behavior |
|---|---|---|
| Shell | Fish PATH differs from Bash | detect active shell and shell-specific config |
| Shell | Non-interactive command lacks aliases/functions | compare interactive and non-interactive signals when possible |
| sudo | `sudo` changes PATH and env | warn when failing command uses sudo or root-owned artifacts exist |
| OS | Immutable distro | avoid suggesting writes to read-only root |
| OS | WSL | detect and label as partial Linux; avoid assuming systemd/GPU behavior |
| OS | Minimal container host | degrade gracefully when commands missing |
| Locale | non-English logs | classify by syscall/evidence, not only English text |
| Paths | spaces/newlines in paths | quote paths safely; JSON encode machine output |
| Permissions | ACLs present | inspect ACLs if mode bits do not explain result |
| Filesystem | case sensitivity mismatch | detect path case conflicts where possible |

### 14.2 Container Edge Cases

| Area | Edge case | Required behavior |
|---|---|---|
| Docker | remote context | show daemon endpoint/context; do not assume local host |
| Docker | socket denied | report permission issue, do not crash |
| Docker | rootless | classify rootless-specific networking/mount behavior |
| Podman | rootless UID mapping | detect UID/GID mismatch and suggest userns strategy |
| Compose | profiles | show inactive services hidden behind profiles |
| Compose | env precedence | explain where the value came from |
| Volumes | stale DB volume | detect schema/version mismatch hints, suggest backup before deletion |
| Ports | IPv6 bind | distinguish IPv4/IPv6 listeners |
| Mounts | bind hides files | compare image target with mounted path when possible |

### 14.3 Runtime Edge Cases

| Area | Edge case | Required behavior |
|---|---|---|
| Node | multiple package managers | rank likely package manager using lockfiles and scripts |
| Python | venv not activated | compare `sys.executable` with expected venv path |
| Python | Poetry uses wrong interpreter | inspect Poetry env info when available |
| .NET | SDK missing but runtime installed | distinguish SDK vs runtime |
| Go | toolchain auto-download | show go env/toolchain behavior |
| Rust | rustup override | inspect directory override and toolchain file |
| CUDA | CPU-only wheel | detect package build variant |
| CUDA | driver/toolkit mismatch | separate driver, toolkit, Python wheel, container runtime |

### 14.4 Git Edge Cases

| Area | Edge case | Required behavior |
|---|---|---|
| Merge | unresolved conflicts | block unsafe checkout suggestions |
| Large files | intentionally tracked binaries | allow policy exceptions |
| Secrets | false positives | show confidence and require review |
| Branch | detached HEAD | explain clearly without panic wording |
| Worktree | multiple worktrees | detect and show worktree context |
| Submodules | uninitialized | suggest safe init/update only when intended |
| LFS | LFS pointers not pulled | detect pointer files and missing lfs install |

### 14.5 Agentic AI Edge Cases

| Area | Edge case | Required behavior |
|---|---|---|
| Prompt injection | malicious README/log | treat external text as data, not instruction |
| Secrets | model context leakage | redact before model call |
| Fixes | hallucinated command | never execute without deterministic validation |
| Sandbox | sandbox differs from host | state validation limits clearly |
| Offline | no LLM available | deterministic diagnosis still works |
| CI | patch passes locally only | include CI parity check before confidence boost |

### 14.6 Safety Edge Cases

| Area | Edge case | Required behavior |
|---|---|---|
| Cleanup | `docker system prune` deletes needed cache | never auto-run; show estimate and risk |
| Ownership | `chown -R` broad path | require path boundary validation and confirmation |
| Firewall | changing rules breaks access | manual-only first |
| SELinux | disabling enforcement | never suggest disabling as primary fix |
| systemd | stopping service impacts other projects | show dependent processes and require confirmation |
| Remote | modifying production server | default remote mode read-only unless explicitly enabled |

---

## 15. Milestone Plan

## Milestone 0 — Product Skeleton and Invariants

**Goal:** Establish non-negotiable architecture and safety model.

**Duration:** 1 week

Deliverables:

- Go CLI skeleton.
- Command parser.
- Global flags.
- Findings schema.
- Rule schema.
- Redaction library.
- Logging/output conventions.
- Test fixture structure.
- Basic `devdiag doctor self`.

Commands:

```bash
devdiag --help
devdiag doctor self
devdiag rules list
```

Exit criteria:

- CLI can run as single binary.
- JSON schema is versioned.
- Redaction tests pass.
- Output respects `--no-color` and non-TTY.
- No collector mutates system.

---

## Milestone 1 — Repo-Aware Static Diagnosis

**Goal:** Understand what the project expects before inspecting the host deeply.

**Duration:** 2–3 weeks

Deliverables:

- Repo parser.
- Package manager detector.
- Runtime requirement detector.
- Env expectation detector.
- Compose/devcontainer detector.
- CI command detector.
- Git basic state detector.
- Markdown/JSON report.

Commands:

```bash
devdiag scan .
devdiag check env
devdiag check runtimes
devdiag check git
```

Supported findings:

- Missing `.env` keys.
- Runtime version mismatch.
- Multiple package managers.
- Tracked `.env` file.
- Missing `.gitignore` patterns.
- README/CI command mismatch.
- Compose references undefined env vars.

Exit criteria:

- Detects top repo-level issues without Docker/system access.
- Works in monorepo with explicit `--path`.
- Produces stable JSON.
- Redacts env values.

---

## Milestone 2 — Host Runtime and Service Collectors

**Goal:** Compare repo expectations with actual Linux host state.

**Duration:** 3–4 weeks

Deliverables:

- Host collector.
- Runtime collector.
- Disk/inode collector.
- Port collector.
- DNS/proxy collector.
- systemd collector.
- Permission collector.

Commands:

```bash
devdiag check ports
devdiag check services
devdiag check network
devdiag check filesystem
devdiag scan . --verbose
```

Supported findings:

- Port conflict.
- Disk full.
- Inode exhaustion.
- Docker daemon inactive.
- systemd service failed.
- Proxy mismatch.
- DNS resolution drift.
- Executable bit missing.
- Wrong owner due to prior sudo.

Exit criteria:

- Partial collector failure does not fail whole scan.
- Findings include evidence and confidence.
- systemd unavailable is handled gracefully.
- No root requirement for normal scan.

---

## Milestone 3 — Docker/Podman Diagnosis

**Goal:** Solve the highest-frequency Linux container dev failures.

**Duration:** 3–4 weeks

Deliverables:

- Docker collector.
- Podman collector.
- Compose config analyzer.
- Container logs parser.
- Mount analyzer.
- UID/GID analyzer.
- Port mapping analyzer.
- SELinux/AppArmor initial checks.

Commands:

```bash
devdiag check containers
devdiag check security
devdiag scan .
```

Supported findings:

- Docker permission denied.
- Docker daemon inactive.
- Podman rootless mount permission issue.
- Compose service unhealthy.
- Port mapping conflict.
- Bind mount hides expected files.
- SELinux label likely missing.
- AppArmor denial likely.
- Stale container/volume from old project.

Exit criteria:

- Works with Docker and Podman when available.
- Does not require Docker socket if no container checks requested.
- Explains rootless-specific failures.
- Does not suggest destructive volume deletion automatically.

---

## Milestone 4 — Repro Runner and Support Capsule

**Goal:** Capture a failing command and generate shareable evidence.

**Duration:** 3 weeks

Deliverables:

- `devdiag repro -- <cmd>`.
- stdout/stderr capture.
- Exit code capture.
- Command timeline.
- Log pattern classifier.
- Capsule create/inspect.
- Strict redaction profile.

Commands:

```bash
devdiag repro -- npm run dev
devdiag repro -- docker compose up
devdiag capsule create
devdiag capsule inspect support.devdiag.tgz
```

Supported findings:

- Address already in use.
- Missing file.
- Permission denied.
- Connection refused.
- Runtime version failure.
- Dependency resolver failure.
- Compose interpolation failure.

Exit criteria:

- Capsule contains enough evidence for teammate debugging.
- Capsule is redacted by default.
- Command output is separated into stdout/stderr.
- `--format ndjson` streams events.

---

## Milestone 5 — Safe Fix Planner

**Goal:** Convert high-confidence findings into dry-run remediation plans.

**Duration:** 2–3 weeks

Deliverables:

- Fix model.
- Dry-run renderer.
- Guarded confirmation flow.
- Rollback metadata.
- Fix tests.
- Policy blocklist.

Commands:

```bash
devdiag scan . --save-report
devdiag fix F-PORT-001 --dry-run
devdiag fix F-PORT-001 --apply
devdiag fix --list
```

Saved-report-based fix commands require an explicit prior `devdiag scan --save-report`.
Plain `devdiag scan` remains non-mutating by default.

Supported fixes:

- Suggest changing Compose port.
- Stop local service with confirmation.
- Add missing `.env` keys as placeholders.
- Add `.env` to `.gitignore`.
- Run `systemctl daemon-reload`.
- Suggest Docker group membership.
- Suggest `chmod +x` for script.

Explicitly blocked:

- Broad `rm -rf`.
- Broad `chown -R /` or home without exact path review.
- Disabling SELinux/AppArmor as default fix.
- Deleting Docker volumes automatically.
- Modifying production remote host by default.

Exit criteria:

- No fix runs by default.
- Every guarded fix has risk text.
- Every applied fix writes an audit entry.
- Risky fixes require TTY confirmation.

---

## Milestone 6 — GPU/CUDA and Advanced Linux AI/ML Pack

**Goal:** Deliver early value to Linux AI/ML developers immediately after Docker/Podman support.

**Duration:** 4 weeks

Deliverables:

- GPU/CUDA analyzer.
- NVIDIA driver and `nvidia-smi` checks.
- PyTorch CUDA wheel validation.
- TensorFlow/JAX GPU validation where applicable.
- NVIDIA Container Toolkit checks.
- GPU visibility inside Docker containers.
- CUDA runtime vs host driver compatibility hints.
- Initial cache analyzer for ML/package caches.
- Secure Boot/NVIDIA module hints.

Commands:

```bash
devdiag check gpu
devdiag check gpu --python
devdiag check containers --gpu
devdiag check cache
devdiag scan . --profile ai-ml
```

Supported findings:

- CPU-only PyTorch wheel.
- PyTorch CUDA wheel installed but GPU unavailable.
- Host sees GPU but container does not.
- NVIDIA Container Toolkit missing or unhealthy.
- Driver appears too old for requested CUDA runtime.
- `LD_LIBRARY_PATH` shadows expected CUDA libraries.
- Secure Boot likely blocks NVIDIA kernel module.
- npm/pip/uv/Go/Docker cache ownership or staleness issue.

Exit criteria:

- GPU checks do not require Python unless a Python/ML project is detected or user asks.
- No GPU system reports `not_applicable`, not failure.
- Container GPU checks are opt-in if they require pulling/running images.
- Cache cleanup is never automatic.

---

## Milestone 7 — Trace Mode

**Goal:** Add syscall-level evidence for hard failures after high-value Linux AI/ML diagnostics are available.

**Duration:** 3–4 weeks

Deliverables:

- `strace` integration.
- Scoped tracing only: `%file`, `%process`, `%network`.
- `--seccomp-bpf` best-effort support.
- Trace-to-finding correlator.
- Trace redaction.
- Trace size/time limits.
- Permission diagnostics.
- Graceful fallback when seccomp-bpf is unavailable.

Commands:

```bash
devdiag trace --scope file -- npm run dev
devdiag trace --scope file,process,network -- python app.py
```

Supported findings:

- Process opened wrong path.
- Missing file caused by wrong cwd.
- Wrong binary executed.
- Permission denied on parent directory.
- Connection refused to expected DB.
- DNS/socket failure.

Exit criteria:

- Trace mode is opt-in.
- If unavailable, DevDiag explains why.
- Trace output is summarized, not dumped.
- Sensitive args/paths are redacted.
- Heavy commands are protected by timeout and syscall filtering.

---

## Milestone 8 — CI/Local Parity and GitHub Action

**Goal:** Detect divergence between local dev, devcontainer, and CI.

**Duration:** 3 weeks

Deliverables:

- GitHub Actions parser.
- CI command/runtime comparison.
- Service parity comparison.
- GitHub Action for DevDiag.
- CI output annotations.

Commands:

```bash
devdiag check ci
devdiag scan . --ci
```

Supported findings:

- CI Node/Python/.NET version differs from local/project files.
- CI uses pnpm while README says npm.
- CI service DB port differs from local compose.
- Devcontainer image differs from CI image.
- CI missing env documented locally.

Exit criteria:

- Can run in GitHub Actions with non-interactive output.
- Produces annotations and JSON artifact.
- Does not expose secrets.
- Exit code behavior is configurable.

---

## Milestone 9 — Remote Environment Sync

**Goal:** Reduce SSH/container/Kubernetes environment disconnect.

**Duration:** 4–6 weeks

Deliverables:

- Remote profile model.
- Temporary dotfile injection.
- Cleanup mechanism.
- Remote diagnostics.
- Container shell support.
- Kubernetes pod support later.

Commands:

```bash
devdiag remote enter user@host
devdiag remote enter container:<id>
devdiag remote sync --profile minimal
devdiag remote clean
```

Exit criteria:

- No permanent remote mutation by default.
- Clean rollback on exit.
- Works without root.
- Clearly reports what changed.

---

## Milestone 10 — Agentic Interceptor and Sandbox

**Goal:** Make DevDiag useful in AI-agent workflows without trusting the agent blindly.

**Duration:** 6–8 weeks

Deliverables:

- Agent-safe evidence bundle.
- BeforeModel/AfterTool-like hooks.
- Local LLM optional explanation.
- Patch sandbox runner.
- AI fix review flow.
- Prompt-injection classifier.

Commands:

```bash
devdiag agent explain F-PORT-001
devdiag agent run -- npm test
devdiag agent sandbox --patch fix.patch -- npm test
```

Exit criteria:

- Deterministic diagnosis works without AI.
- AI context is redacted.
- External text cannot become model instructions.
- Patches require diff review.
- Sandbox results clearly state limitations.

---

## Milestone 11 — Team Product Layer

**Goal:** Turn local CLI trust into team adoption.

**Duration:** after open-source traction

Deliverables:

- Policy packs.
- Rule pack registry.
- Team baseline configs.
- Capsule viewer.
- Issue template generator.
- VS Code/Zed extension.
- Enterprise redaction policies.

Monetizable features:

- Private rule packs.
- Team dashboard for recurring failures.
- Capsule search/viewer.
- Organization policy enforcement.
- CI reporting.
- Priority support.

Open-source core should remain useful without the paid layer.

---

## 16. Repo Structure Proposal

```text
devdiag/
├── cmd/devdiag/
│   └── main.go
├── internal/cli/
├── internal/output/
├── internal/logging/
├── internal/redact/
├── internal/schema/
├── internal/repo/
│   ├── node/
│   ├── python/
│   ├── dotnet/
│   ├── go/
│   ├── rust/
│   ├── docker/
│   ├── devcontainer/
│   └── ci/
├── internal/collectors/
│   ├── host/
│   ├── shell/
│   ├── runtimes/
│   ├── containers/
│   ├── network/
│   ├── services/
│   ├── filesystem/
│   ├── security/
│   └── gpu/
├── internal/graph/
├── internal/rules/
├── internal/findings/
├── internal/fix/
├── internal/repro/
├── internal/trace/
├── internal/capsule/
├── rules/
│   ├── env.yaml
│   ├── runtimes.yaml
│   ├── docker.yaml
│   ├── podman.yaml
│   ├── network.yaml
│   ├── systemd.yaml
│   ├── git.yaml
│   ├── ci.yaml
│   └── gpu.yaml
├── fixtures/
│   ├── node-port-conflict/
│   ├── python-wrong-version/
│   ├── compose-env-missing/
│   ├── podman-uid-mismatch/
│   ├── selinux-denied/
│   └── gpu-cpu-wheel/
├── docs/
└── .github/workflows/
```

---

## 17. Testing Strategy

### 17.1 Unit Tests

- Parsers.
- Redaction.
- Rule evaluation.
- Confidence calculation.
- Output formatting.
- Fix rendering.

### 17.2 Fixture Tests

Each finding must have at least one fixture.

Fixture structure:

```text
fixtures/node-port-conflict/
├── repo/
├── host.json
├── container.json
├── command.stderr.log
├── expected.findings.json
└── expected.report.md
```

### 17.3 Integration Tests

Run in containers/VMs for:

- Docker available.
- Podman rootless.
- No systemd.
- systemd host.
- SELinux enforcing image/host where possible.
- No GPU.
- GPU runner optional.

### 17.4 Golden Output Tests

- Human output stable.
- JSON schema stable.
- NDJSON valid.
- No ANSI when `NO_COLOR`.
- No color when non-TTY.
- Secrets redacted.

### 17.5 Chaos/Edge Tests

- Missing commands.
- Permission denied collectors.
- Huge logs.
- Malformed YAML.
- Binary files.
- Broken symlinks.
- Non-UTF-8 output.
- Paths with spaces/newlines.
- Interrupted command.
- User presses Ctrl+C.

---

## 18. Security Principles

1. Local-first.
2. No upload by default.
3. No mutation by default.
4. No secret printing by default.
5. No broad privileged access by default.
6. eBPF and privileged tracing are opt-in.
7. Docker socket is treated as sensitive.
8. AI is optional and sandboxed.
9. External text is untrusted.
10. Fixes are transparent and reviewable.

---

## 19. Product Differentiation

DevDiag wins if it does this better than existing tools:

```text
Not just: Docker says port failed.
But: compose.yaml requires 5432, host postgres owns it, CI uses 5433, and the recommended safe fix is to change local host port to avoid stopping another project.
```

```text
Not just: Permission denied.
But: container user is uid=1000, workspace is owned by uid=503, Podman rootless is active, SELinux is enforcing, and the strongest cause is UID/GID mismatch rather than chmod.
```

```text
Not just: torch.cuda.is_available() is false.
But: Python env uses CPU-only torch wheel while host driver sees GPU and container runtime lacks NVIDIA hook.
```

The differentiation is **correlation**, not collection.

---

## 20. MVP Cut Line

If time is limited, ship this first:

```text
scan
check env
check runtimes
check containers
check ports
check git
repro
markdown/json output
redaction
no fix apply yet, only recommendations
```

Do not delay MVP for:

- eBPF.
- AI.
- Remote sync.
- GPU deep support.
- Editor extension.
- Team dashboard.

---

## 21. Recommended First 30 Days

### Week 1

- Create Go CLI skeleton.
- Define schema.
- Define rule format.
- Implement output modes.
- Implement redaction.
- Implement fixtures.

### Week 2

- Repo parser for Node/Python/Docker Compose/.env/Git.
- Runtime version checks.
- Env missing/extra checks.
- Git tracked secret/large file checks.

### Week 3

- Host collectors: ports, disk, PATH, shell, services basic.
- Docker collector basic.
- First 10 findings.
- Markdown/JSON reports.

### Week 4

- `repro -- <cmd>`.
- stdout/stderr capture.
- Log classifiers.
- Capsule draft.
- Golden output tests.
- Public demo fixtures.

---

## 22. First 12 Findings to Implement

1. `F-ENV-001` — Missing required env var.
2. `F-ENV-002` — Compose references undefined env var.
3. `F-RUNTIME-001` — Node version mismatch.
4. `F-RUNTIME-002` — Python version mismatch.
5. `F-PORT-001` — Host port collision.
6. `F-DOCKER-001` — Docker daemon inactive or inaccessible.
7. `F-CONTAINER-001` — Compose service unhealthy.
8. `F-FS-001` — Script missing executable bit.
9. `F-GIT-001` — `.env` tracked by Git.
10. `F-DISK-001` — Disk or inode exhaustion.
11. `F-CACHE-001` — Package/build cache is unwritable or root-owned.
12. `F-GPU-001` — ML framework installed without usable GPU acceleration.

---

## 23. First Demo Scenarios

### Demo 1 — Missing Env

```bash
devdiag scan examples/missing-env
```

Shows missing `DATABASE_URL` and `JWT_SECRET`.

### Demo 2 — Port Conflict

```bash
devdiag repro -- docker compose up
```

Shows port 5432 conflict with evidence from Compose and `ss`.

### Demo 3 — Runtime Mismatch

```bash
devdiag scan examples/node-version
```

Shows `.nvmrc` expects 22 but active Node is 20.

### Demo 4 — Docker Permission

```bash
devdiag check containers
```

Shows Docker socket permission denied and safe next steps.

### Demo 5 — Git Secret Guardrail

```bash
devdiag check git
```

Shows `.env` tracked and suggests `.gitignore` update.

---

## 24. Final Product Strategy

Build DevDiag in this order:

```text
1. Deterministic Linux diagnostic CLI
2. Evidence graph + rule engine
3. Repro runner + capsule
4. Safe fix planner
5. Deep Linux packs: Podman, SELinux, systemd, GPU
6. CI/local parity
7. Remote environment sync
8. Agentic AI interceptor and sandbox
9. Team workflow product
```

The strategic mistake would be starting with AI or a giant workflow orchestrator.

The correct wedge is:

> DevDiag explains why a project fails on a Linux workstation using real evidence.

Once that is trusted, every other layer becomes natural.

---

## 25. One-Sentence Pitch

**DevDiag is a Linux-first diagnostic CLI that correlates repo metadata, host state, containers, services, logs, and optional traces to explain broken developer environments with evidence and safe fixes.**
