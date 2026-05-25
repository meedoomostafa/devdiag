# M3 Security Verification

Date: 2026-05-24

## Scope

This note records verification for M3 Docker/Podman diagnosis and Linux security
evidence. M3 counts complete for the current non-mutating Docker, Podman,
Compose, SELinux, and AppArmor acceptance surface.

## Implemented Contract

The current security collector and M1 rules now verify these behaviors locally:

- `check security` and `scan` collect non-mutating SELinux/AppArmor state and
  bounded denial evidence.
- Security log scanning can correlate SELinux multi-line audit records by audit
  ID, so a denial line can be attributed to the scanned project root when a
  companion `CWD` record contains that root.
- Root filtering still excludes unrelated denial records from other projects.
- SELinux container-domain denials against generic host labels emit
  `container_label_hint=mount_relabel_z_or_Z` evidence.
- `F-SEC-SELINUX-001` includes non-destructive container relabel guidance when
  that label hint is present. It does not suggest disabling SELinux.
- `F-SEC-APPARMOR-001` includes AppArmor profile review guidance when
  `docker-default` profile evidence is present. It does not suggest disabling
  AppArmor.
- Podman rootless evidence includes modern network/runtime signals such as
  `podman_network_backend`, `podman_rootless_network_cmd`,
  `podman_pasta_executable`, `podman_slirp4netns_executable`,
  UID/GID map counts from `idMappings`, and rootless run-root evidence.
- Podman runtime-directory failures emit `podman_runtime_dir_error=true`, and
  the Podman finding includes specific `/run/user` rootless guidance.

## Targeted Commands

```bash
env PATH=/usr/local/go/bin:$PATH \
  GOCACHE=/tmp/devdiag-go-build \
  GOMODCACHE=/tmp/devdiag-go-mod \
  XDG_CACHE_HOME=/tmp/devdiag-cache \
  /usr/local/go/bin/go test ./internal/collectors/security ./internal/collectors/podman ./internal/rules -run 'TestCollector_ReadsSELinuxAndAppArmorDenials|TestCollector_FiltersDenialsByRootWhenProvided|TestCollector_AttributesSELinuxDenialUsingAuditRecordContext|TestCollector_UsesCommandRunnerForPodmanProbes|TestCollector_PodmanRuntimeDirFailureEvidence|TestM1Engine_SecurityRules|TestM1Engine_PodmanRules' -count=1
```

Live-gated Docker/Podman collector acceptance:

```bash
env PATH=/usr/local/go/bin:$PATH \
  GOCACHE=/tmp/devdiag-go-build \
  GOMODCACHE=/tmp/devdiag-go-mod \
  XDG_CACHE_HOME=/tmp/devdiag-cache \
  DEVDIAG_LIVE_M3_CONTAINERS=1 \
  /usr/local/go/bin/go test ./internal/cli -run TestCheckContainersLiveDockerPodmanCollectors -count=1 -v
```

Observed on 2026-05-24:

- Docker server was reachable at version `29.5.0`.
- Podman `info` succeeded rootless with `netavark`.
- The live-gated test passed and verified Docker and Podman collectors in JSON
  output.

## Future Hardening

Deeper runtime mount attribution from real container metadata remains future
hardening. It is not required for the current M3 count because the implemented
security collector and container collectors are read-only and expose explicit
evidence without mutating Docker or Podman state.
