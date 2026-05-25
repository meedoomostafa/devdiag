#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GO_BIN="${GO_BIN:-/usr/local/go/bin/go}"
GOCACHE_DIR="${GOCACHE:-/tmp/devdiag-go-build}"
GOMODCACHE_DIR="${GOMODCACHE:-/tmp/devdiag-go-mod}"
XDG_CACHE_DIR="${XDG_CACHE_HOME:-/tmp/devdiag-cache}"
CLUSTER="${DEVDIAG_KIND_CLUSTER:-devdiag-live}"
NAMESPACE="${DEVDIAG_KIND_NAMESPACE:-devdiag-live}"
POD="${DEVDIAG_KIND_POD:-devdiag-target}"
IMAGE="${DEVDIAG_KIND_IMAGE:-busybox:1.36}"
CONTEXT="kind-${CLUSTER}"
TARGET="k8s:${CONTEXT}/${NAMESPACE}/${POD}"
EVIDENCE="${DEVDIAG_K8S_EVIDENCE:-${ROOT_DIR}/docs/release/evidence/m12-k8s-kind-signoff.md}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/devdiag-k8s-signoff.XXXXXX")"
BIN_DIR="${TMP_DIR}/bin"
RUN_LOG="${TMP_DIR}/commands.tsv"
CLEANUP_RESULT="not run"
FINISHED=0

mkdir -p "${BIN_DIR}" "$(dirname "${EVIDENCE}")"
touch "${RUN_LOG}"

cleanup_tmp() {
	if [[ "${DEVDIAG_KEEP_SIGNOFF_TMP:-0}" != "1" ]]; then
		rm -rf "${TMP_DIR}"
	fi
}

need() {
	local cmd="$1"
	if ! command -v "${cmd}" >/dev/null 2>&1; then
		echo "missing required command: ${cmd}" >&2
		return 1
	fi
}

capture_version() {
	local name="$1"
	shift
	local stdout_file="${TMP_DIR}/version-${name}.stdout"
	local stderr_file="${TMP_DIR}/version-${name}.stderr"
	{
		printf '### %s\n\n' "${name}"
		if "$@" >"${stdout_file}" 2>"${stderr_file}"; then
			sed -n '1,20p' "${stdout_file}"
		else
			cat "${stderr_file}"
		fi
		printf '\n'
	} >>"${TMP_DIR}/versions.md"
}

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
		echo "command ${name} exited ${code}, expected ${expected}" >&2
		sed -n '1,120p' "${stderr_file}" >&2
		return "${code}"
	fi
}

selected_json() {
	local file="$1"
	if [[ ! -f "${file}" ]]; then
		printf '_missing output_\n'
		return
	fi
	grep -E '"status"|"session_id"|"remote_dir"|"cleanup_command"|"redaction_status"' "${file}" | sed -n '1,40p' || true
}

cleanup_kind() {
	if [[ "${DEVDIAG_KEEP_KIND:-0}" == "1" ]]; then
		CLEANUP_RESULT="skipped because DEVDIAG_KEEP_KIND=1"
		return 0
	fi
	if ! command -v kind >/dev/null 2>&1; then
		CLEANUP_RESULT="skipped because kind is unavailable"
		return 0
	fi
	if kind get clusters 2>/dev/null | grep -qx "${CLUSTER}"; then
		if kind delete cluster --name "${CLUSTER}" >"${TMP_DIR}/kind-delete.stdout" 2>"${TMP_DIR}/kind-delete.stderr"; then
			CLEANUP_RESULT="kind cluster ${CLUSTER} deleted"
		else
			CLEANUP_RESULT="kind cluster ${CLUSTER} cleanup failed"
			return 1
		fi
	else
		CLEANUP_RESULT="kind cluster ${CLUSTER} already absent"
	fi
}

write_evidence() {
	local status="$1"
	local commit
	commit="$(git -C "${ROOT_DIR}" rev-parse HEAD 2>/dev/null || printf unknown)"
	local date_utc
	date_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	{
		printf '# M12 Kubernetes Kind Live Signoff Evidence\n\n'
		printf 'Date: %s\n\n' "${date_utc}"
		printf 'Commit: `%s`\n\n' "${commit}"
		printf 'Status: `%s`\n\n' "${status}"
		printf 'Target: `%s`\n\n' "${TARGET}"
		printf 'Cluster: `%s`\n\n' "${CLUSTER}"
		printf 'Namespace: `%s`\n\n' "${NAMESPACE}"
		printf 'Pod: `%s`\n\n' "${POD}"
		printf 'Image: `%s`\n\n' "${IMAGE}"
		printf 'Cleanup: %s\n\n' "${CLEANUP_RESULT}"
		printf '## Tool Versions\n\n'
		if [[ -f "${TMP_DIR}/versions.md" ]]; then
			cat "${TMP_DIR}/versions.md"
		else
			printf '_not collected_\n\n'
		fi
		printf '## Command Results\n\n'
		printf '| Command | Exit | Expected |\n'
		printf '| --- | ---: | ---: |\n'
		while IFS=$'\t' read -r name code expected _; do
			[[ -z "${name}" ]] && continue
			printf '| `%s` | `%s` | `%s` |\n' "${name}" "${code}" "${expected}"
		done <"${RUN_LOG}"
		printf '\n## Selected JSON Evidence\n\n'
		for name in doctor sync-dry-run sync status enter-dry-run clean; do
			printf '### %s\n\n```json\n' "${name}"
			selected_json "${TMP_DIR}/${name}.stdout"
			printf '```\n\n'
		done
		printf '## Live Test Output\n\n```text\n'
		if [[ -f "${TMP_DIR}/go-live-test.stdout" ]]; then
			sed -n '1,160p' "${TMP_DIR}/go-live-test.stdout"
		fi
		if [[ -f "${TMP_DIR}/go-live-test.stderr" ]]; then
			sed -n '1,160p' "${TMP_DIR}/go-live-test.stderr"
		fi
		printf '```\n'
	} >"${EVIDENCE}"
}

finish_failure() {
	local code="${1:-1}"
	trap - EXIT
	if [[ ! "${code}" =~ ^[0-9]+$ ]]; then
		code=1
	fi
	if [[ "${FINISHED}" == "1" ]]; then
		exit "${code}"
	fi
	cleanup_kind || true
	write_evidence "failed"
	FINISHED=1
	cleanup_tmp
	exit "${code}"
}

trap 'finish_failure $?' EXIT

need docker || finish_failure 127
need kind || finish_failure 127
need kubectl || finish_failure 127
if [[ ! -x "${GO_BIN}" ]]; then
	echo "go binary is not executable: ${GO_BIN}" >&2
	finish_failure 127
fi
docker info >/dev/null 2>&1 || {
	echo "docker daemon is not reachable" >&2
	finish_failure 1
}

capture_version "go" "${GO_BIN}" version
capture_version "docker" docker version
capture_version "kind" kind version
capture_version "kubectl" kubectl version --client=true

if kind get clusters | grep -qx "${CLUSTER}"; then
	kind delete cluster --name "${CLUSTER}" >/dev/null
fi
kind create cluster --name "${CLUSTER}"
kubectl --context "${CONTEXT}" create namespace "${NAMESPACE}" --dry-run=client -o yaml |
	kubectl --context "${CONTEXT}" apply -f -
for _ in $(seq 1 60); do
	if kubectl --context "${CONTEXT}" -n "${NAMESPACE}" get serviceaccount default >/dev/null 2>&1; then
		break
	fi
	sleep 1
done
kubectl --context "${CONTEXT}" -n "${NAMESPACE}" get serviceaccount default >/dev/null
kubectl --context "${CONTEXT}" -n "${NAMESPACE}" apply -f - <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: ${POD}
  labels:
    app.kubernetes.io/name: devdiag-live-target
spec:
  restartPolicy: Always
  containers:
    - name: shell
      image: ${IMAGE}
      command: ["sh", "-lc", "sleep 3600"]
YAML
kubectl --context "${CONTEXT}" -n "${NAMESPACE}" wait --for=condition=Ready "pod/${POD}" --timeout=120s

(
	cd "${ROOT_DIR}"
	PATH="${BIN_DIR}:${PATH}" \
		GOCACHE="${GOCACHE_DIR}" \
		GOMODCACHE="${GOMODCACHE_DIR}" \
		XDG_CACHE_HOME="${XDG_CACHE_DIR}" \
		"${GO_BIN}" build -o "${BIN_DIR}/devdiag" ./cmd/devdiag
)

cd "${ROOT_DIR}"

LIVE_ENV=(
	"PATH=${BIN_DIR}:${PATH}"
	"GOCACHE=${GOCACHE_DIR}"
	"GOMODCACHE=${GOMODCACHE_DIR}"
	"XDG_CACHE_HOME=${TMP_DIR}/cache"
	"DEVDIAG_LIVE_K8S_TARGET=${TARGET}"
)
record_command "go-live-test" 0 env "${LIVE_ENV[@]}" "${GO_BIN}" test ./internal/cli -run TestRemoteLiveKubernetesVerification -count=1 -v

CLI_ENV=(
	"PATH=${BIN_DIR}:${PATH}"
	"XDG_CACHE_HOME=${TMP_DIR}/cli-cache"
)
record_command "doctor" 0 env "${CLI_ENV[@]}" devdiag remote doctor "${TARGET}" --format json
record_command "sync-dry-run" 0 env "${CLI_ENV[@]}" devdiag remote sync "${TARGET}" --dry-run --format json
record_command "sync" 0 env "${CLI_ENV[@]}" devdiag remote sync "${TARGET}" --format json
SESSION_ID="$(sed -n 's/.*"session_id": "\([^"]*\)".*/\1/p' "${TMP_DIR}/sync.stdout" | head -n 1)"
if [[ -z "${SESSION_ID}" ]]; then
	echo "remote sync JSON did not include session_id" >&2
	finish_failure 1
fi
record_command "status" 0 env "${CLI_ENV[@]}" devdiag remote status "${TARGET}" --format json
record_command "enter-dry-run" 0 env "${CLI_ENV[@]}" devdiag remote enter "${TARGET}" --dry-run --format json
record_command "clean" 0 env "${CLI_ENV[@]}" devdiag remote clean "${TARGET}" --session "${SESSION_ID}" --format json

cleanup_kind
write_evidence "passed"
FINISHED=1
cleanup_tmp
trap - EXIT
