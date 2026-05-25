# M12 Kubernetes Kind Live Signoff Evidence

Date: 2026-05-25T07:36:31Z

Commit: `dc501639ada468a68494d0af0c12bc7a51e7e97f`

Status: `passed`

Target: `k8s:kind-devdiag-live/devdiag-live/devdiag-target`

Cluster: `devdiag-live`

Namespace: `devdiag-live`

Pod: `devdiag-target`

Image: `busybox:1.36`

Cleanup: kind cluster devdiag-live deleted

## Tool Versions

### go

go version go1.25.0 linux/amd64

### docker

Client: Docker Engine - Community
 Version:           29.5.0
 API version:       1.54
 Go version:        go1.26.3
 Git commit:        98f1464
 Built:             Thu May 14 14:44:21 2026
 OS/Arch:           linux/amd64
 Context:           default

Server: Docker Engine - Community
 Engine:
  Version:          29.5.0
  API version:      1.54 (minimum version 1.40)
  Go version:       go1.26.3
  Git commit:       ff8d90a
  Built:            Thu May 14 14:40:25 2026
  OS/Arch:          linux/amd64
  Experimental:     false
 containerd:
  Version:          v2.2.3

### kind

kind v0.31.0 go1.25.0 linux/amd64

### kubectl

Client Version: v1.36.1
Kustomize Version: v5.8.1

## Command Results

| Command | Exit | Expected |
| --- | ---: | ---: |
| `go-live-test` | `0` | `0` |
| `doctor` | `0` | `0` |
| `sync-dry-run` | `0` | `0` |
| `sync` | `0` | `0` |
| `status` | `0` | `0` |
| `enter-dry-run` | `0` | `0` |
| `clean` | `0` | `0` |

## Selected JSON Evidence

### doctor

```json
  "status": "doctor",
  "redaction_status": "default"
```

### sync-dry-run

```json
  "status": "synced",
  "session_id": "20260525T073629Z_34ca69",
  "remote_dir": "/tmp/devdiag-remote/20260525T073629Z_34ca69",
  "cleanup_command": "devdiag remote clean k8s:kind-devdiag-live/devdiag-live/devdiag-target --session 20260525T073629Z_34ca69",
  "redaction_status": "default"
```

### sync

```json
  "status": "synced",
  "session_id": "20260525T073629Z_d67d0f",
  "remote_dir": "/tmp/devdiag-remote/20260525T073629Z_d67d0f",
  "cleanup_command": "devdiag remote clean k8s:kind-devdiag-live/devdiag-live/devdiag-target --session 20260525T073629Z_d67d0f",
  "redaction_status": "default"
```

### status

```json
  "status": "active",
  "session_id": "20260525T073629Z_d67d0f",
  "remote_dir": "/tmp/devdiag-remote/20260525T073629Z_d67d0f",
  "redaction_status": "default"
```

### enter-dry-run

```json
  "status": "planned",
  "session_id": "20260525T073629Z_4159b9",
  "remote_dir": "/tmp/devdiag-remote/20260525T073629Z_4159b9",
  "cleanup_command": "devdiag remote clean k8s:kind-devdiag-live/devdiag-live/devdiag-target --session 20260525T073629Z_4159b9",
  "redaction_status": "default"
```

### clean

```json
  "status": "cleaned",
  "session_id": "20260525T073629Z_d67d0f",
  "cleanup_command": "devdiag remote clean k8s:kind-devdiag-live/devdiag-live/devdiag-target --session 20260525T073629Z_d67d0f",
  "redaction_status": "default"
```

## Live Test Output

```text
=== RUN   TestRemoteLiveKubernetesVerification
--- PASS: TestRemoteLiveKubernetesVerification (1.30s)
PASS
ok  	github.com/meedoomostafa/devdiag/internal/cli	2.387s
```
