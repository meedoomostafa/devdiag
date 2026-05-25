#!/usr/bin/env bash
set -uo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GO_BIN="${GO_BIN:-/usr/local/go/bin/go}"
GOCACHE_DIR="${GOCACHE:-/tmp/devdiag-go-build}"
GOMODCACHE_DIR="${GOMODCACHE:-/tmp/devdiag-go-mod}"
XDG_CACHE_DIR="${XDG_CACHE_HOME:-/tmp/devdiag-cache}"
EVIDENCE="${DEVDIAG_RELEASE_EVIDENCE:-${ROOT_DIR}/docs/release/final-live-signoff.md}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/devdiag-release-signoff.XXXXXX")"
RUN_LOG="${TMP_DIR}/commands.tsv"
ARTIFACT_DIR="${TMP_DIR}/artifacts"
WORKFLOW="${DEVDIAG_ACTION_SIGNOFF_WORKFLOW:-action-live-signoff.yml}"
BRANCH="${DEVDIAG_SIGNOFF_BRANCH:-}"
REPO="${DEVDIAG_SIGNOFF_REPO:-}"
FAILURES=0
ACTION_RUN_ID=""
ACTION_RUN_URL=""

mkdir -p "$(dirname "${EVIDENCE}")" "${ARTIFACT_DIR}"
touch "${RUN_LOG}"

cleanup() {
	if [[ "${DEVDIAG_KEEP_SIGNOFF_TMP:-0}" != "1" ]]; then
		rm -rf "${TMP_DIR}"
	fi
}
trap cleanup EXIT

record_result() {
	local name="$1"
	local code="$2"
	local expected="$3"
	shift 3
	printf '%s\t%s\t%s\t%s\n' "${name}" "${code}" "${expected}" "$*" >>"${RUN_LOG}"
	if [[ "${code}" != "${expected}" ]]; then
		FAILURES=$((FAILURES + 1))
		return 1
	fi
	return 0
}

run_command() {
	local name="$1"
	local expected="$2"
	shift 2
	local stdout_file="${TMP_DIR}/${name}.stdout"
	local stderr_file="${TMP_DIR}/${name}.stderr"
	set +e
	"$@" >"${stdout_file}" 2>"${stderr_file}"
	local code=$?
	set -u
	record_result "${name}" "${code}" "${expected}" "$@" || {
		echo "command ${name} exited ${code}, expected ${expected}" >&2
		sed -n '1,120p' "${stderr_file}" >&2
	}
	return "${code}"
}

capture_env() {
	{
		printf '### go\n\n'
		if [[ -x "${GO_BIN}" ]]; then
			"${GO_BIN}" version 2>&1 || true
		else
			printf 'missing or not executable: %s\n' "${GO_BIN}"
		fi
		printf '\n### git\n\n'
		git -C "${ROOT_DIR}" --version 2>&1 || true
		printf 'commit=%s\n' "$(git -C "${ROOT_DIR}" rev-parse HEAD 2>/dev/null || printf unknown)"
		printf 'branch=%s\n' "${BRANCH:-unknown}"
		printf '\n### host\n\n'
		uname -a 2>&1 || true
		printf '\n### kind\n\n'
		kind version 2>&1 || printf 'not installed\n'
		printf '\n### kubectl\n\n'
		kubectl version --client=true 2>&1 || printf 'not installed\n'
		printf '\n### docker\n\n'
		docker version 2>&1 || printf 'not installed or unavailable\n'
		printf '\n### gh\n\n'
		gh --version 2>&1 || printf 'not installed\n'
	} >"${TMP_DIR}/environment.md"
}

write_evidence() {
	local status="$1"
	local commit
	commit="$(git -C "${ROOT_DIR}" rev-parse HEAD 2>/dev/null || printf unknown)"
	local date_utc
	date_utc="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	{
		printf '# DevDiag Final Live Signoff\n\n'
		printf 'Date: %s\n\n' "${date_utc}"
		printf 'Commit: `%s`\n\n' "${commit}"
		printf 'Branch: `%s`\n\n' "${BRANCH:-unknown}"
		printf 'Status: `%s`\n\n' "${status}"
		if [[ -n "${ACTION_RUN_URL}" ]]; then
			printf 'GitHub Action run: %s\n\n' "${ACTION_RUN_URL}"
		fi
		printf '## Environment\n\n'
		cat "${TMP_DIR}/environment.md"
		printf '\n## Command Results\n\n'
		printf '| Command | Exit | Expected |\n'
		printf '| --- | ---: | ---: |\n'
		while IFS=$'\t' read -r name code expected _; do
			[[ -z "${name}" ]] && continue
			printf '| `%s` | `%s` | `%s` |\n' "${name}" "${code}" "${expected}"
		done <"${RUN_LOG}"
		printf '\n## GitHub Action Evidence\n\n'
		if [[ -n "${ACTION_RUN_ID}" ]]; then
			printf '- Run ID: `%s`\n' "${ACTION_RUN_ID}"
			printf '- Run URL: %s\n' "${ACTION_RUN_URL}"
		else
			printf '_No GitHub Action run ID recorded._\n'
		fi
		if [[ -f "${TMP_DIR}/action-run.json" ]]; then
			printf '\n```json\n'
			sed -n '1,160p' "${TMP_DIR}/action-run.json"
			printf '\n```\n'
		fi
		printf '\n## Artifact Hashes\n\n'
		if [[ -f "${TMP_DIR}/artifact-sha256.txt" ]]; then
			printf '```text\n'
			cat "${TMP_DIR}/artifact-sha256.txt"
			printf '```\n'
		else
			printf '_No downloaded artifact hashes recorded._\n'
		fi
	} >"${EVIDENCE}"
}

require_clean_tree() {
	if ! git -C "${ROOT_DIR}" diff --quiet || ! git -C "${ROOT_DIR}" diff --cached --quiet; then
		echo "worktree has uncommitted tracked changes; commit or stash before final signoff" >&2
		return 1
	fi
	if [[ -n "$(git -C "${ROOT_DIR}" status --porcelain --untracked-files=normal)" ]]; then
		echo "worktree has untracked files; commit or remove them before final signoff" >&2
		return 1
	fi
}

dispatch_action_signoff() {
	if ! command -v gh >/dev/null 2>&1; then
		echo "gh is required for GitHub Action signoff" >&2
		return 127
	fi
	if [[ -z "${REPO}" ]]; then
		REPO="$(gh repo view --json nameWithOwner --jq .nameWithOwner)"
	fi
	if [[ -z "${BRANCH}" ]]; then
		BRANCH="$(git -C "${ROOT_DIR}" branch --show-current)"
	fi
	local head
	head="$(git -C "${ROOT_DIR}" rev-parse HEAD)"
	local remote_head
	remote_head="$(git -C "${ROOT_DIR}" ls-remote origin "refs/heads/${BRANCH}" | awk '{print $1}')"
	if [[ "${remote_head}" != "${head}" ]]; then
		echo "remote branch ${BRANCH} is not at local HEAD ${head}" >&2
		return 1
	fi
	if ! gh workflow run "${WORKFLOW}" --repo "${REPO}" --ref "${BRANCH}" >"${TMP_DIR}/workflow-dispatch.stdout" 2>"${TMP_DIR}/workflow-dispatch.stderr"; then
		cat "${TMP_DIR}/workflow-dispatch.stderr" >&2
		return 1
	fi
	for _ in $(seq 1 30); do
		gh run list --repo "${REPO}" --workflow "${WORKFLOW}" --branch "${BRANCH}" --event workflow_dispatch --limit 5 \
			--json databaseId,headSha,status,conclusion,url,createdAt >"${TMP_DIR}/recent-action-runs.json" || true
		ACTION_RUN_ID="$(jq -r --arg head "${head}" 'map(select(.headSha == $head)) | sort_by(.createdAt) | last | .databaseId // empty' "${TMP_DIR}/recent-action-runs.json")"
		ACTION_RUN_URL="$(jq -r --arg head "${head}" 'map(select(.headSha == $head)) | sort_by(.createdAt) | last | .url // empty' "${TMP_DIR}/recent-action-runs.json")"
		if [[ -n "${ACTION_RUN_ID}" ]]; then
			break
		fi
		sleep 2
	done
	if [[ -z "${ACTION_RUN_ID}" ]]; then
		echo "could not find dispatched ${WORKFLOW} run for ${head}" >&2
		return 1
	fi
	set +e
	gh run watch "${ACTION_RUN_ID}" --repo "${REPO}" --exit-status >"${TMP_DIR}/action-watch.stdout" 2>"${TMP_DIR}/action-watch.stderr"
	local watch_code=$?
	set -u
	gh run view "${ACTION_RUN_ID}" --repo "${REPO}" --json databaseId,status,conclusion,headSha,url,createdAt,updatedAt,jobs >"${TMP_DIR}/action-run.json" 2>"${TMP_DIR}/action-run.stderr" || true
	if [[ "${watch_code}" != "0" ]]; then
		sed -n '1,160p' "${TMP_DIR}/action-watch.stderr" >&2
		return "${watch_code}"
	fi
	for artifact in devdiag-report-1.25 devdiag-report-1.26; do
		local out_dir="${ARTIFACT_DIR}/${artifact}"
		mkdir -p "${out_dir}"
		gh run download "${ACTION_RUN_ID}" --repo "${REPO}" -n "${artifact}" -D "${out_dir}" || return 1
		jq -e '.schema_version and .collectors and .findings' "${out_dir}/devdiag-report.json" >/dev/null || return 1
		if grep -q 'secret123' "${out_dir}/devdiag-report.json"; then
			echo "downloaded artifact ${artifact} leaked secret123" >&2
			return 1
		fi
	done
	find "${ARTIFACT_DIR}" -type f -name 'devdiag-report.json' -print0 | sort -z | xargs -0 sha256sum >"${TMP_DIR}/artifact-sha256.txt"
}

cd "${ROOT_DIR}" || exit 1
if [[ -z "${BRANCH}" ]]; then
	BRANCH="$(git branch --show-current)"
fi
capture_env

run_command "go-test" 0 env PATH="/usr/local/go/bin:${PATH}" GOCACHE="${GOCACHE_DIR}" GOMODCACHE="${GOMODCACHE_DIR}" XDG_CACHE_HOME="${XDG_CACHE_DIR}" "${GO_BIN}" test ./... -count=1
run_command "go-vet" 0 env PATH="/usr/local/go/bin:${PATH}" GOCACHE="${GOCACHE_DIR}" GOMODCACHE="${GOMODCACHE_DIR}" XDG_CACHE_HOME="${XDG_CACHE_DIR}" "${GO_BIN}" vet ./...
run_command "go-build" 0 env PATH="/usr/local/go/bin:${PATH}" GOCACHE="${GOCACHE_DIR}" GOMODCACHE="${GOMODCACHE_DIR}" XDG_CACHE_HOME="${XDG_CACHE_DIR}" "${GO_BIN}" build -o /tmp/devdiag-plan-check ./cmd/devdiag
run_command "git-diff-check" 0 git diff --check
run_command "worktree-clean-start" 0 require_clean_tree
run_command "k8s-kind-signoff" 0 scripts/live/k8s-kind-signoff.sh
run_command "trace-signoff" 0 scripts/live/trace-signoff.sh
run_command "github-action-signoff" 0 dispatch_action_signoff

if [[ "${FAILURES}" == "0" ]]; then
	write_evidence "passed"
else
	write_evidence "failed"
fi

exit "${FAILURES}"
