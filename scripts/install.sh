#!/usr/bin/env bash
set -euo pipefail

REPO="${DEVDIAG_REPO:-meedoomostafa/devdiag}"
VERSION="${DEVDIAG_INSTALL_VERSION:-v0.1.0}"
BIN_DIR="${DEVDIAG_BIN_DIR:-}"
SHA256="${DEVDIAG_ARCHIVE_SHA256:-}"
REQUIRE_CHECKSUM="${DEVDIAG_REQUIRE_CHECKSUM:-0}"
DRY_RUN=0

usage() {
	cat <<'USAGE'
DevDiag installer for Linux.

Builds DevDiag from the selected GitHub ref and installs the binary.

Usage:
  scripts/install.sh [--version <ref>] [--bin-dir <dir>] [--sha256 <hex>] [--dry-run]

Environment:
  DEVDIAG_INSTALL_VERSION  Git ref to install. Default: v0.1.0
  DEVDIAG_BIN_DIR          Install directory. Default: /usr/local/bin if writable, else ~/.local/bin
  DEVDIAG_REPO             GitHub repo owner/name. Default: meedoomostafa/devdiag
  DEVDIAG_ARCHIVE_SHA256   Expected SHA256 checksum of the source archive
  DEVDIAG_REQUIRE_CHECKSUM If 1, fail if no checksum is provided
  GITHUB_TOKEN or GH_TOKEN GitHub token for private repository archive downloads

Examples:
  curl -fsSL https://raw.githubusercontent.com/meedoomostafa/devdiag/v0.1.0/scripts/install.sh | bash
  curl -fsSL https://raw.githubusercontent.com/meedoomostafa/devdiag/v0.1.0/scripts/install.sh | bash -s -- --sha256 <hex>
  DEVDIAG_INSTALL_VERSION=main bash scripts/install.sh --dry-run
USAGE
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--version)
			[[ $# -ge 2 ]] || {
				echo "--version requires a value" >&2
				exit 2
			}
			VERSION="$2"
			shift 2
			;;
		--bin-dir)
			[[ $# -ge 2 ]] || {
				echo "--bin-dir requires a value" >&2
				exit 2
			}
			BIN_DIR="$2"
			shift 2
			;;
		--sha256)
			[[ $# -ge 2 ]] || {
				echo "--sha256 requires a value" >&2
				exit 2
			}
			SHA256="$2"
			shift 2
			;;
		--dry-run)
			DRY_RUN=1
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "unknown option: $1" >&2
			usage >&2
			exit 2
			;;
	esac
done

need() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 127
	fi
}

go_version_ok() {
	local version major minor
	version="$(go version | awk '{print $3}' | sed 's/^go//; s/[a-z].*$//')"
	major="${version%%.*}"
	minor="${version#*.}"
	minor="${minor%%.*}"
	[[ "${major}" =~ ^[0-9]+$ ]] || return 1
	[[ "${minor}" =~ ^[0-9]+$ ]] || return 1
	if (( major > 1 )); then
		return 0
	fi
	if (( major == 1 && minor >= 25 )); then
		return 0
	fi
	return 1
}

default_bin_dir() {
	if [[ -n "${BIN_DIR}" ]]; then
		printf '%s\n' "${BIN_DIR}"
		return
	fi
	if [[ -d /usr/local/bin && -w /usr/local/bin ]]; then
		printf '/usr/local/bin\n'
		return
	fi
	printf '%s/.local/bin\n' "${HOME}"
}

archive_url() {
	case "${VERSION}" in
		refs/*)
			printf 'https://github.com/%s/archive/%s.tar.gz\n' "${REPO}" "${VERSION}"
			;;
		v[0-9]*)
			printf 'https://github.com/%s/archive/refs/tags/%s.tar.gz\n' "${REPO}" "${VERSION}"
			;;
		*)
			if [[ "${VERSION}" =~ ^[0-9a-f]{40}$ ]]; then
				printf 'https://github.com/%s/archive/%s.tar.gz\n' "${REPO}" "${VERSION}"
			else
				printf 'https://github.com/%s/archive/refs/heads/%s.tar.gz\n' "${REPO}" "${VERSION}"
			fi
			;;
	esac
}

download() {
	local url="$1"
	local out="$2"
	local token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
	if command -v curl >/dev/null 2>&1; then
		if [[ -n "${token}" ]]; then
			curl -fsSL -H "Authorization: Bearer ${token}" "${url}" -o "${out}"
		else
			curl -fsSL "${url}" -o "${out}"
		fi
	elif command -v wget >/dev/null 2>&1; then
		if [[ -n "${token}" ]]; then
			wget --header="Authorization: Bearer ${token}" -qO "${out}" "${url}"
		else
			wget -qO "${out}" "${url}"
		fi
	else
		echo "missing required command: curl or wget" >&2
		exit 127
	fi
}

OS_NAME="$(uname -s | tr '[:upper:]' '[:lower:]')"
if [[ "${OS_NAME}" != "linux" ]]; then
	echo "DevDiag installer supports Linux. On Windows, use WSL2 or build from source with Go." >&2
	exit 2
fi

need go
need tar
need mktemp

if ! go_version_ok; then
	echo "Go 1.25 or newer is required; found: $(go version)" >&2
	exit 2
fi

TARGET_DIR="$(default_bin_dir)"
URL="$(archive_url)"

if [[ "${DRY_RUN}" == "1" ]]; then
	cat <<EOF
repo=${REPO}
version=${VERSION}
archive=${URL}
bin_dir=${TARGET_DIR}
go=$(go version)
EOF
	exit 0
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/devdiag-install.XXXXXX")"
cleanup() {
	rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

ARCHIVE="${TMP_DIR}/devdiag.tar.gz"
SRC_DIR="${TMP_DIR}/src"
OUT="${TMP_DIR}/devdiag"

download "${URL}" "${ARCHIVE}"

if [[ -n "${SHA256}" ]]; then
	echo "Verifying checksum..."
	if command -v sha256sum >/dev/null 2>&1; then
		echo "${SHA256}  ${ARCHIVE}" | sha256sum -c -
	elif command -v shasum >/dev/null 2>&1; then
		echo "${SHA256}  ${ARCHIVE}" | shasum -a 256 -c -
	else
		echo "error: sha256sum or shasum not found; cannot verify checksum" >&2
		exit 1
	fi
elif [[ "${REQUIRE_CHECKSUM}" == "1" ]]; then
	echo "error: DEVDIAG_REQUIRE_CHECKSUM=1 set but no checksum provided" >&2
	exit 1
fi

mkdir -p "${SRC_DIR}"
tar -xzf "${ARCHIVE}" -C "${SRC_DIR}" --strip-components=1

(
	cd "${SRC_DIR}"
	CGO_ENABLED=0 go build -trimpath \
		-ldflags "-s -w -X github.com/meedoomostafa/devdiag/internal/version.Version=${VERSION}" \
		-o "${OUT}" ./cmd/devdiag
)

mkdir -p "${TARGET_DIR}"
cp "${OUT}" "${TARGET_DIR}/devdiag"
chmod 0755 "${TARGET_DIR}/devdiag"

echo "DevDiag ${VERSION} installed to ${TARGET_DIR}/devdiag"
if ! command -v devdiag >/dev/null 2>&1; then
	echo "Add ${TARGET_DIR} to PATH to run devdiag from any shell." >&2
fi
