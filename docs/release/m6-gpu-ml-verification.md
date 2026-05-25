# M6 GPU/CUDA and AI/ML Verification

Date: 2026-05-24

## Scope

This note records verification for M6 GPU, CUDA, ML framework, Docker GPU, and
cache diagnostics. M6 counts complete for the current evidence and rule surface.

## Implemented Contract

- NVIDIA hardware detection records `gpu_present`, `gpu_hardware_detected`,
  `gpu_nvidia_module_loaded`, `gpu_nvidia_smi_status`, and
  `gpu_nvidia_smi_exit_code` where applicable.
- No-GPU hosts report `applicable: false` and do not emit GPU findings.
- CUDA collection records `cuda_runtime_version` from `nvcc --version`.
- CUDA compatibility evidence records `cuda_driver_supported_version` and
  `cuda_compatibility` when both `nvcc` and `nvidia-smi` expose compatible
  evidence.
- Python ML probes cover PyTorch, TensorFlow, and JAX GPU visibility.
- Docker GPU collection records NVIDIA Container Toolkit evidence, Docker
  runtime evidence, and opt-in `docker_gpu_verify_result`.
- Docker GPU verification is non-pulling by default. If the image is not local
  and `--allow-pull` is not set, the verifier records `image_missing`.
- Cache collection records package cache path, size, writability, and owner UID.
- M6 rules cover host GPU driver failures, Secure Boot suspicion, Python ML GPU
  mismatch, Docker GPU runtime/verification failures, and cache ownership.

## Targeted Commands

```bash
env PATH=/usr/local/go/bin:$PATH \
  GOCACHE=/tmp/devdiag-go-build \
  GOMODCACHE=/tmp/devdiag-go-mod \
  XDG_CACHE_HOME=/tmp/devdiag-cache \
  /usr/local/go/bin/go test ./internal/collectors/gpu ./internal/collectors/cuda ./internal/collectors/gpudocker ./internal/collectors/cache ./internal/rules ./internal/cli -run 'TestCollectorNoNvidiaSMI|TestCollectorNvidiaSMIErrorWithHardwareFallbackEmitsStatusEvidence|TestCollectorCUDACompatibility|TestCollectorGPUVerify|TestCollectorPipCache|TestM6Engine|TestCheckGPU' -count=1
```

Live-gated Docker GPU verification:

```bash
env PATH=/usr/local/go/bin:$PATH \
  GOCACHE=/tmp/devdiag-go-build \
  GOMODCACHE=/tmp/devdiag-go-mod \
  XDG_CACHE_HOME=/tmp/devdiag-cache \
  DEVDIAG_LIVE_M6_DOCKER_GPU=1 \
  /usr/local/go/bin/go test ./internal/cli -run TestCheckGPULiveDockerVerification -count=1 -v
```

Optional image and pull controls:

```bash
DEVDIAG_LIVE_M6_DOCKER_GPU_IMAGE=nvidia/cuda:12.2.0-base-ubuntu22.04
DEVDIAG_LIVE_M6_DOCKER_GPU_ALLOW_PULL=1
```

Observed on 2026-05-24:

- `nvidia-smi` reported `NVIDIA GeForce RTX 3050 Laptop GPU` with driver
  `580.159.03`.
- Docker server was reachable at version `29.5.0`.
- The default CUDA verification image was not present locally, so the live gate
  passed by recording Docker GPU verification evidence without pulling or
  running a container.

## Future Hardening

A host with a preloaded CUDA verification image or explicit pull permission can
prove successful `docker run --gpus all ... nvidia-smi`. That live success path
is useful release evidence but is not required for M6 counting because success,
failure, timeout, and image-missing paths are covered by deterministic tests and
the live gate exercises the real Docker path safely.
