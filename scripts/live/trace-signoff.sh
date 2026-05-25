#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GO_BIN="${GO_BIN:-/usr/local/go/bin/go}"
GOCACHE_DIR="${GOCACHE:-/tmp/devdiag-go-build}"
GOMODCACHE_DIR="${GOMODCACHE:-/tmp/devdiag-go-mod}"
XDG_CACHE_DIR="${XDG_CACHE_HOME:-/tmp/devdiag-cache}"
EVIDENCE="${DEVDIAG_TRACE_EVIDENCE:-${ROOT_DIR}/docs/release/evidence/m13-trace-ebpf-signoff.md}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/devdiag-trace-signoff.XXXXXX")"
BIN_DIR="${TMP_DIR}/bin"
RUN_LOG="${TMP_DIR}/commands.tsv"
USE_DOCKER="${DEVDIAG_TRACE_USE_DOCKER:-1}"
FAILURES=0

mkdir -p "${BIN_DIR}" "$(dirname "${EVIDENCE}")"
touch "${RUN_LOG}"

cleanup() {
	if [[ "${DEVDIAG_KEEP_SIGNOFF_TMP:-0}" != "1" ]]; then
		rm -rf "${TMP_DIR}"
	fi
}
trap cleanup EXIT

record_command() {
	local name="$1"
	local expected="$2"
	shift 2
	local stdout_file="${TMP_DIR}/${name}.stdout"
	local stderr_file="${TMP_DIR}/${name}.stderr"
	set +e
	"$@" >"${stdout_file}" 2>"${stderr_file}"
	local code=$?
	set -e
	printf '%s\t%s\t%s\t%s\n' "${name}" "${code}" "${expected}" "$*" >>"${RUN_LOG}"
	if [[ "${code}" != "${expected}" ]]; then
		FAILURES=$((FAILURES + 1))
		echo "command ${name} exited ${code}, expected ${expected}" >&2
		sed -n '1,120p' "${stderr_file}" >&2
	fi
}

capture_versions() {
	{
		printf '### go\n\n'
		"${GO_BIN}" version 2>&1 || true
		printf '\n### host\n\n'
		uname -a 2>&1 || true
		printf '\n### capabilities\n\n'
		grep -E 'CapEff|CapPrm|CapBnd' /proc/self/status 2>&1 || true
		printf '\n### btf\n\n'
		if [[ -e /sys/kernel/btf/vmlinux ]]; then
			printf 'present\n'
		else
			printf 'missing\n'
		fi
		printf '\n### sysctl\n\n'
		printf 'kernel.perf_event_paranoid='
		cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || true
		printf 'kernel.unprivileged_bpf_disabled='
		cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || true
		printf '\n### docker\n\n'
		if command -v docker >/dev/null 2>&1; then
			docker version 2>&1 || true
		else
			printf 'not installed\n'
		fi
	} >"${TMP_DIR}/versions.md"
}

write_evidence() {
	local status="$1"
	local commit
	commit="$(git -C "${ROOT_DIR}" rev-parse HEAD 2>/dev/null || printf unknown)"
	local date_utc
	date_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	{
		printf '# M13 Trace and eBPF Live Signoff Evidence\n\n'
		printf 'Date: %s\n\n' "${date_utc}"
		printf 'Commit: `%s`\n\n' "${commit}"
		printf 'Status: `%s`\n\n' "${status}"
		printf '## Environment\n\n'
		cat "${TMP_DIR}/versions.md"
		printf '\n## Command Results\n\n'
		printf '| Command | Exit | Expected |\n'
		printf '| --- | ---: | ---: |\n'
		while IFS=$'\t' read -r name code expected _; do
			[[ -z "${name}" ]] && continue
			printf '| `%s` | `%s` | `%s` |\n' "${name}" "${code}" "${expected}"
		done <"${RUN_LOG}"
		printf '\n## Output Excerpts\n\n'
		for name in deterministic-tests ebpf-unavailable strace-live ebpf-live; do
			printf '### %s stdout\n\n```text\n' "${name}"
			if [[ -f "${TMP_DIR}/${name}.stdout" ]]; then
				sed -n '1,180p' "${TMP_DIR}/${name}.stdout"
			fi
			printf '```\n\n'
			printf '### %s stderr\n\n```text\n' "${name}"
			if [[ -f "${TMP_DIR}/${name}.stderr" ]]; then
				sed -n '1,180p' "${TMP_DIR}/${name}.stderr"
			fi
			printf '```\n\n'
		done
	} >"${EVIDENCE}"
}

if [[ ! -x "${GO_BIN}" ]]; then
	echo "go binary is not executable: ${GO_BIN}" >&2
	exit 127
fi

capture_versions

cd "${ROOT_DIR}"
record_command "deterministic-tests" 0 env \
	PATH="/usr/local/go/bin:${PATH}" \
	GOCACHE="${GOCACHE_DIR}" \
	GOMODCACHE="${GOMODCACHE_DIR}" \
	XDG_CACHE_HOME="${XDG_CACHE_DIR}" \
	"${GO_BIN}" test ./internal/trace ./internal/cli \
	-run 'TestCheckEBPFSupportReportsMissingBTFAndCapabilities|TestCheckEBPFSupportReportsFeatureProbeFailure|TestEBPFTracepointsAreScoped|TestEBPFRecordsMapToExistingFindingsAndFilterProcessTree|TestEBPFKernelEventsDecodeToExistingTraceFindings|TestEBPFKernelEventsRespectRequestedScopes|TestTraceCommand_EBPFBackendUnavailableDiagnostic|TestTraceCommand_EBPFBackendUnavailableJSONIncludesEvidence' \
	-count=1 -v

record_command "build-devdiag" 0 env \
	PATH="/usr/local/go/bin:${PATH}" \
	GOCACHE="${GOCACHE_DIR}" \
	GOMODCACHE="${GOMODCACHE_DIR}" \
	XDG_CACHE_HOME="${XDG_CACHE_DIR}" \
	"${GO_BIN}" build -o "${BIN_DIR}/devdiag" ./cmd/devdiag

record_command "ebpf-unavailable" 7 env \
	PATH="${BIN_DIR}:${PATH}" \
	XDG_CACHE_HOME="${TMP_DIR}/cache-unavailable" \
	devdiag trace --backend ebpf --scope file,network --format json -- true

if command -v strace >/dev/null 2>&1; then
	record_command "strace-live" 0 env \
		PATH="/usr/local/go/bin:${PATH}" \
		GOCACHE="${GOCACHE_DIR}" \
		GOMODCACHE="${GOMODCACHE_DIR}" \
		XDG_CACHE_HOME="${XDG_CACHE_DIR}" \
		DEVDIAG_LIVE_M7_STRACE=1 \
		"${GO_BIN}" test ./internal/cli -run TestTraceCommand_LiveStraceJSONAcceptance -count=1 -v
elif [[ "${USE_DOCKER}" == "1" ]] && command -v docker >/dev/null 2>&1; then
	record_command "strace-live" 0 docker run --rm \
		-v "${ROOT_DIR}:/workspace" \
		-w /workspace \
		-e GOFLAGS=-buildvcs=false \
		-e GOCACHE=/tmp/devdiag-go-build \
		-e GOMODCACHE=/tmp/devdiag-go-mod \
		-e XDG_CACHE_HOME=/tmp/devdiag-cache \
		-e DEVDIAG_LIVE_M7_STRACE=1 \
		golang:1.25-bookworm \
		sh -lc 'apt-get update >/tmp/devdiag-apt-update.log && apt-get install -y strace >/tmp/devdiag-apt-install.log && PATH=/usr/local/go/bin:$PATH /usr/local/go/bin/go test ./internal/cli -run TestTraceCommand_LiveStraceJSONAcceptance -count=1 -v'
else
	printf '%s\t%s\t%s\t%s\n' "strace-live" "not-run" "0" "strace not installed and docker signoff disabled" >>"${RUN_LOG}"
	FAILURES=$((FAILURES + 1))
fi

if [[ "${DEVDIAG_LIVE_EBPF:-}" == "1" ]]; then
	record_command "ebpf-live" 0 env \
		PATH="/usr/local/go/bin:${PATH}" \
		GOCACHE="${GOCACHE_DIR}" \
		GOMODCACHE="${GOMODCACHE_DIR}" \
		XDG_CACHE_HOME="${XDG_CACHE_DIR}" \
		DEVDIAG_LIVE_EBPF=1 \
		"${GO_BIN}" test ./internal/cli -run TestTraceCommand_LiveEBPFJSONAcceptance -count=1 -v
elif [[ "${USE_DOCKER}" == "1" ]] && command -v docker >/dev/null 2>&1; then
	record_command "ebpf-live" 0 docker run --rm \
		--privileged \
		--cgroupns=host \
		--userns=host \
		--pid=host \
		--security-opt seccomp=unconfined \
		--security-opt apparmor=unconfined \
		--security-opt label=disable \
		-v /sys/kernel/btf:/sys/kernel/btf:ro \
		-v /sys/kernel/tracing:/sys/kernel/tracing \
		-v /sys/kernel/debug:/sys/kernel/debug \
		-v "${ROOT_DIR}:/workspace" \
		-w /workspace \
		-e GOFLAGS=-buildvcs=false \
		-e GOCACHE=/tmp/devdiag-go-build \
		-e GOMODCACHE=/tmp/devdiag-go-mod \
		-e XDG_CACHE_HOME=/tmp/devdiag-cache \
		-e DEVDIAG_LIVE_EBPF=1 \
		golang:1.25-bookworm \
		sh -lc 'old=$(cat /proc/sys/kernel/perf_event_paranoid); echo -1 > /proc/sys/kernel/perf_event_paranoid; trap "echo $old > /proc/sys/kernel/perf_event_paranoid" EXIT; /usr/local/go/bin/go test ./internal/cli -run TestTraceCommand_LiveEBPFJSONAcceptance -count=1 -v'
else
	printf '%s\t%s\t%s\t%s\n' "ebpf-live" "not-run" "0" "DEVDIAG_LIVE_EBPF not set and docker signoff disabled" >>"${RUN_LOG}"
	FAILURES=$((FAILURES + 1))
fi

if [[ "${FAILURES}" == "0" ]]; then
	write_evidence "passed"
else
	write_evidence "failed"
fi

exit "${FAILURES}"
