# M12 Kubernetes Remote Verification

Date: 2026-05-25

M12 replaces the earlier Kubernetes "unsupported" remote behavior with a real
`kubectl exec` transport while preserving M9 remote contracts for JSON output,
non-mutating dry-runs, failed upload exit codes, and manifest-driven cleanup.

## Scope

Implemented public commands:

- `devdiag remote doctor k8s:namespace/pod`
- `devdiag remote doctor k8s:context/namespace/pod`
- `devdiag remote sync k8s:namespace/pod`
- `devdiag remote enter k8s:namespace/pod`
- `devdiag remote clean k8s:namespace/pod`
- `devdiag remote status k8s:namespace/pod`

Implemented option:

- `--k8s-container <name>` selects the container for multi-container pods.

Remote files are staged under `/tmp/devdiag-remote/<session>`.

## Transport Behavior

The Kubernetes transport uses `kubectl exec` only:

- Probe:
  `kubectl [--context <context>] -n <namespace> exec <pod> [-c <container>] -- sh -lc <fact-script>`
- Run:
  `kubectl [--context <context>] -n <namespace> exec [-i] <pod> [-c <container>] -- <command...>`
- Upload:
  `tar -C <stageDir> -cf - . | kubectl ... exec -i <pod> -- sh -lc 'mkdir -p <remoteDir> && tar -C <remoteDir> -xf -'`
- Enter:
  `kubectl ... exec -it <pod> -- sh -lc 'export DEVDDIR=...; . "$DEVDDIR/env.sh"; exec "${SHELL:-sh}"'`
- Clean:
  reuses the same manifest cleanup path as SSH and container targets.

## Automated Verification

Run:

```bash
PATH=/usr/local/go/bin:$PATH \
GOCACHE=/tmp/devdiag-go-build \
GOMODCACHE=/tmp/devdiag-go-mod \
XDG_CACHE_HOME=/tmp/devdiag-cache \
/usr/local/go/bin/go test ./internal/remote/target ./internal/remote/transport/k8s ./internal/remote/session ./internal/cli \
  -run 'TestParse|TestKubectlBaseArgsUseContextNamespaceAndContainer|TestProbeUsesKubectlExecAndParsesFacts|TestRunUsesKubectlExecWithStdin|TestUploadTarsLocalDirIntoKubectlExec|TestValidateRootDir|TestValidateRootDir_Hardening|TestRemoteKubernetesTargetsDryRunAndStatusJSON|TestRemoteKubernetesDoctorUsesKubectlAndContainerFlag|TestRemoteKubernetesSyncUploadFailureReturnsJSON|TestRemoteKubernetesStatusUsesCache|TestRemoteKubernetesCleanExitPaths|TestRemoteLiveKubernetesVerification' \
  -count=1
```

Expected:

- K8s target parsing accepts `k8s:namespace/pod` and
  `k8s:context/namespace/pod`.
- K8s target parsing rejects shell metacharacters.
- `kubectl` arguments preserve context, namespace, pod, and container name.
- `remote <doctor|sync|enter|clean|status> ... --dry-run --format json`
  returns valid JSON and exit code `0`.
- Failed K8s upload returns valid JSON with `status: "failed"` and exit code
  `6`.
- K8s status reads the local session cache.
- K8s clean refuses unsafe cached roots with exit code `5`.
- K8s partial cleanup returns valid JSON with `status: "partial"` and exit code
  `3`.
- K8s successful cleanup returns valid JSON with `status: "cleaned"`.
- Live K8s verification is skipped unless `DEVDIAG_LIVE_K8S_TARGET` is set.

## Live Gate

For release signoff, run the disposable kind harness:

```bash
PATH=/tmp/devdiag-live-tools/bin:$PATH \
GOCACHE=/tmp/devdiag-go-build \
GOMODCACHE=/tmp/devdiag-go-mod \
XDG_CACHE_HOME=/tmp/devdiag-cache \
scripts/live/k8s-kind-signoff.sh
```

The harness requires `docker`, `kind`, `kubectl`, and the Go toolchain. It
creates a disposable `kind` cluster named `devdiag-live`, starts a pod with
`sh` and `tar`, runs the live Go verification, runs direct CLI smokes for
`doctor`, `sync`, `status`, `enter --dry-run`, and `clean`, records sanitized
evidence, and deletes the cluster unless `DEVDIAG_KEEP_KIND=1` is set.

Recorded evidence:

- [evidence/m12-k8s-kind-signoff.md](evidence/m12-k8s-kind-signoff.md)

To run against an explicit existing pod instead:

```bash
PATH=/usr/local/go/bin:$PATH \
GOCACHE=/tmp/devdiag-go-build \
GOMODCACHE=/tmp/devdiag-go-mod \
XDG_CACHE_HOME=/tmp/devdiag-cache \
DEVDIAG_LIVE_K8S_TARGET=k8s:<context>/<namespace>/<pod> \
DEVDIAG_LIVE_K8S_CONTAINER=<container-name> \
/usr/local/go/bin/go test ./internal/cli -run TestRemoteLiveKubernetesVerification -count=1 -v
```

For single-container pods, omit `DEVDIAG_LIVE_K8S_CONTAINER`.

The live gate verifies:

- doctor;
- dry-run sync;
- real sync;
- status;
- enter planning;
- partial cleanup;
- final cleanup.

## Live Signoff Recorded

The disposable kind signoff passed on 2026-05-25. The evidence file records the
tool versions, target, command exits, selected JSON snippets, live test output,
and cluster cleanup result.
