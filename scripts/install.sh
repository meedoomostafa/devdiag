#!/usr/bin/env bash
set -euo pipefail

REPO="${DEVDIAG_REPO:-meedoomostafa/devdiag}"
VERSION="${DEVDIAG_INSTALL_VERSION:-latest}"
BIN_DIR="${DEVDIAG_BIN_DIR:-}"
SHA256="${DEVDIAG_ARCHIVE_SHA256:-}"
REQUIRE_CHECKSUM="${DEVDIAG_REQUIRE_CHECKSUM:-0}"
DRY_RUN=0

ADD_TO_PATH=0
NO_ADD_TO_PATH=0
PRINT_PATH_COMMAND=0
SHELL_TARGET="auto"
GITHUB_API_BASE="${DEVDIAG_GITHUB_API_BASE_URL:-https://api.github.com}"

usage() {
	cat <<'USAGE'
DevDiag installer for Linux.

Builds DevDiag from the selected GitHub ref and installs the binary.

Usage:
  scripts/install.sh [--version <ref>] [--bin-dir <dir>] [--sha256 <hex>] [--dry-run]
                     [--add-to-path] [--no-add-to-path] [--print-path-command]
                     [--shell <auto|bash|zsh|fish|all>]

Environment:
  DEVDIAG_INSTALL_VERSION  Git ref to install. Default: latest
  DEVDIAG_BIN_DIR          Install directory. Default: /usr/local/bin if writable, else ~/.local/bin
  DEVDIAG_REPO             GitHub repo owner/name. Default: meedoomostafa/devdiag
  DEVDIAG_ARCHIVE_SHA256   Expected SHA256 checksum of the source archive
  DEVDIAG_REQUIRE_CHECKSUM If 1, fail if no checksum is provided
  DEVDIAG_GITHUB_API_BASE_URL Custom GitHub API base URL (for tests). Default: https://api.github.com
  GITHUB_TOKEN or GH_TOKEN GitHub token for private repository archive downloads

Examples:
  curl -fsSL -o install.sh https://raw.githubusercontent.com/meedoomostafa/devdiag/main/scripts/install.sh
  bash install.sh
  DEVDIAG_INSTALL_VERSION=v0.2.7 bash install.sh
  bash install.sh --add-to-path
USAGE
}

REQUESTED_VERSION="${VERSION}"

while [[ $# -gt 0 ]]; do
	case "$1" in
		--version)
			[[ $# -ge 2 ]] || {
				echo "--version requires a value" >&2
				exit 2
			}
			VERSION="$2"
			REQUESTED_VERSION="$2"
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
		--add-to-path)
			ADD_TO_PATH=1
			shift
			;;
		--no-add-to-path)
			NO_ADD_TO_PATH=1
			shift
			;;
		--print-path-command)
			PRINT_PATH_COMMAND=1
			shift
			;;
		--shell)
			[[ $# -ge 2 ]] || {
				echo "--shell requires a value" >&2
				exit 2
			}
			SHELL_TARGET="$2"
			shift 2
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

if [[ "${ADD_TO_PATH}" == "1" && "${NO_ADD_TO_PATH}" == "1" ]]; then
	echo "error: cannot specify both --add-to-path and --no-add-to-path" >&2
	exit 2
fi

case "${SHELL_TARGET}" in
	auto|bash|zsh|fish|all) ;;
	*)
		echo "error: invalid value for --shell: ${SHELL_TARGET} (allowed: auto, bash, zsh, fish, all)" >&2
		exit 2
		;;
esac

json_escape() {
	printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

strip_version() {
	local v="$1"
	v="${v#refs/tags/}"
	v="${v#refs/heads/}"
	v="${v#v}"
	printf '%s\n' "${v}"
}

detect_shell() {
	local shell_path="$1"
	case "${shell_path}" in
		*bash) echo "bash" ;;
		*zsh) echo "zsh" ;;
		*fish) echo "fish" ;;
		*) echo "unknown" ;;
	esac
}

is_in_path() {
	local dir="$1"
	case ":${PATH}:" in
		*":${dir}:"*) return 0 ;;
		*) return 1 ;;
	esac
}

read_metadata() {
	local metadata_dir="${XDG_CONFIG_HOME:-$HOME/.config}/devdiag"
	local metadata_path="${metadata_dir}/install.json"

	if [[ -f "${metadata_path}" ]]; then
		if ! grep -q '"resolved_version"' "${metadata_path}" || ! grep -q '"binary_path"' "${metadata_path}"; then
			echo "warning: existing metadata at ${metadata_path} is malformed" >&2
			return 0
		fi

		local exist_version exist_binary
		exist_version="$(grep '"resolved_version"' "${metadata_path}" | head -n1 | sed -n 's/.*"resolved_version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' || true)"
		exist_binary="$(grep '"binary_path"' "${metadata_path}" | head -n1 | sed -n 's/.*"binary_path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' || true)"

		if [[ -n "${exist_version}" && -n "${exist_binary}" ]]; then
			echo "Existing DevDiag installation found:"
			echo "version: ${exist_version}"
			echo "binary: ${exist_binary}"
		else
			echo "warning: existing metadata at ${metadata_path} is malformed" >&2
		fi
	fi
}

write_metadata() {
	local metadata_dir="${XDG_CONFIG_HOME:-$HOME/.config}/devdiag"
	local metadata_path="${metadata_dir}/install.json"

	if ! mkdir -p "${metadata_dir}"; then
		echo "warning: could not create metadata directory ${metadata_dir}" >&2
		return 0
	fi
	chmod 0755 "${metadata_dir}"

	local installed_at
	installed_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

	local checksum_req="false"
	if [[ "${REQUIRE_CHECKSUM}" == "1" ]]; then
		checksum_req="true"
	fi

	local checksum_prov="false"
	if [[ -n "${SHA256}" ]]; then
		checksum_prov="true"
	fi

	local esc_repo esc_ref esc_resolved esc_dir esc_bin esc_url
	esc_repo="$(json_escape "${REPO}")"
	esc_ref="$(json_escape "${VERSION}")"
	esc_resolved="$(json_escape "${RESOLVED_VERSION}")"
	esc_dir="$(json_escape "${TARGET_DIR}")"
	esc_bin="$(json_escape "${INSTALL_PATH}")"
	esc_url="$(json_escape "${URL}")"

	cat > "${metadata_path}" <<EOF
{
  "schema_version": "1",
  "repo": "${esc_repo}",
  "source_ref": "${esc_ref}",
  "resolved_version": "${esc_resolved}",
  "install_dir": "${esc_dir}",
  "binary_path": "${esc_bin}",
  "installed_at": "${installed_at}",
  "install_method": "source-archive",
  "archive_url": "${esc_url}",
  "checksum_required": ${checksum_req},
  "checksum_provided": ${checksum_prov}
}
EOF
	chmod 0644 "${metadata_path}"
}

update_sh_profile() {
	local file="$1"
	local display_path="$2"

	if [[ ! -f "${file}" ]]; then
		touch "${file}"
	fi

	local block="# >>> devdiag PATH >>>
case \":\$PATH:\" in
  *\":${display_path}:\"*) ;;
  *) export PATH=\"${display_path}:\$PATH\" ;;
esac
# <<< devdiag PATH <<<"

	if grep -q "# >>> devdiag PATH >>>" "${file}"; then
		if grep -A 5 "# >>> devdiag PATH >>>" "${file}" | grep -q "${display_path}"; then
			return 0
		fi

		local tmp_profile
		tmp_profile="$(mktemp "${TMPDIR:-/tmp}/devdiag-profile.XXXXXX")"

		awk -v new_block="${block}" '
		BEGIN { in_block = 0 }
		/# >>> devdiag PATH >>>/ {
			in_block = 1
			print new_block
			next
		}
		/# <<< devdiag PATH <<</ {
			in_block = 0
			next
		}
		{
			if (!in_block) {
				print $0
			}
		}
		' "${file}" > "${tmp_profile}"

		mv "${tmp_profile}" "${file}"
	else
		printf "\n%s\n" "${block}" >> "${file}"
	fi
}

update_fish_profile() {
	local file="$1"
	local display_path="$2"

	local dir
	dir="$(dirname "${file}")"
	mkdir -p "${dir}"

	if [[ ! -f "${file}" ]]; then
		touch "${file}"
	fi

	local block="# >>> devdiag PATH >>>
fish_add_path \"${display_path}\"
# <<< devdiag PATH <<<"

	if grep -q "# >>> devdiag PATH >>>" "${file}"; then
		if grep -A 5 "# >>> devdiag PATH >>>" "${file}" | grep -q "${display_path}"; then
			return 0
		fi

		local tmp_profile
		tmp_profile="$(mktemp "${TMPDIR:-/tmp}/devdiag-profile.XXXXXX")"

		awk -v new_block="${block}" '
		BEGIN { in_block = 0 }
		/# >>> devdiag PATH >>>/ {
			in_block = 1
			print new_block
			next
		}
		/# <<< devdiag PATH <<</ {
			in_block = 0
			next
		}
		{
			if (!in_block) {
				print $0
			}
		}
		' "${file}" > "${tmp_profile}"

		mv "${tmp_profile}" "${file}"
	else
		printf "\n%s\n" "${block}" >> "${file}"
	fi
}

print_path_command() {
	local display_path="${TARGET_DIR}"
	if [[ "${TARGET_DIR}" == "${HOME}"* ]]; then
		display_path="\$HOME${TARGET_DIR#${HOME}}"
	fi

	local target_sh="${SHELL_TARGET}"
	if [[ "${target_sh}" == "auto" ]]; then
		target_sh="${CURRENT_SHELL}"
	fi

	case "${target_sh}" in
		fish)
			echo "fish_add_path \"${display_path}\""
			;;
		*)
			echo "export PATH=\"${display_path}:\$PATH\""
			;;
	esac
}

resolve_latest_version() {
	local api="${GITHUB_API_BASE}/repos/${REPO}/releases/latest"
	local token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
	local json

	if command -v curl >/dev/null 2>&1; then
		if [[ -n "${token}" ]]; then
			json="$(curl -fsSL \
				-H "Accept: application/vnd.github+json" \
				-H "Authorization: Bearer ${token}" \
				"${api}")"
		else
			json="$(curl -fsSL \
				-H "Accept: application/vnd.github+json" \
				"${api}")"
		fi
	elif command -v wget >/dev/null 2>&1; then
		if [[ -n "${token}" ]]; then
			json="$(wget --header="Accept: application/vnd.github+json" \
				--header="Authorization: Bearer ${token}" \
				-qO- "${api}")"
		else
			json="$(wget --header="Accept: application/vnd.github+json" \
				-qO- "${api}")"
		fi
	else
		echo "missing required command: curl or wget" >&2
		exit 127
	fi

	printf '%s\n' "${json}" \
		| sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
		| head -n1
}

if [[ "${VERSION}" == "latest" ]]; then
	VERSION="$(resolve_latest_version)"
	if [[ -z "${VERSION}" ]]; then
		echo "error: could not resolve latest DevDiag release" >&2
		exit 1
	fi
fi

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

if [[ -d "/usr/local/go/bin" ]]; then
	export PATH="/usr/local/go/bin:${PATH}"
fi

need go
need tar
need mktemp

if ! go_version_ok; then
	echo "Go 1.25 or newer is required; found: $(go version)" >&2
	exit 2
fi

RESOLVED_VERSION="$(strip_version "${VERSION}")"
APP_VERSION="${RESOLVED_VERSION}"
URL="$(archive_url)"
TARGET_DIR="$(default_bin_dir)"
INSTALL_PATH="${TARGET_DIR}/devdiag"
METADATA_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/devdiag"
METADATA_PATH="${METADATA_DIR}/install.json"

if is_in_path "${TARGET_DIR}"; then
	PATH_STATUS="already_on_path"
else
	PATH_STATUS="not_on_path"
fi

CURRENT_SHELL="$(detect_shell "${SHELL:-}")"

UPDATE_BASH=0
UPDATE_ZSH=0
UPDATE_FISH=0

if [[ "${SHELL_TARGET}" == "auto" ]]; then
	case "${CURRENT_SHELL}" in
		bash) UPDATE_BASH=1 ;;
		zsh) UPDATE_ZSH=1 ;;
		fish) UPDATE_FISH=1 ;;
	esac
elif [[ "${SHELL_TARGET}" == "bash" ]]; then
	UPDATE_BASH=1
elif [[ "${SHELL_TARGET}" == "zsh" ]]; then
	UPDATE_ZSH=1
elif [[ "${SHELL_TARGET}" == "fish" ]]; then
	UPDATE_FISH=1
elif [[ "${SHELL_TARGET}" == "all" ]]; then
	if [[ -f "${HOME}/.bashrc" || -f "${HOME}/.profile" ]]; then
		UPDATE_BASH=1
	fi
	if [[ -f "${HOME}/.zshrc" ]]; then
		UPDATE_ZSH=1
	fi
	if [[ -f "${HOME}/.config/fish/config.fish" || -d "${HOME}/.config/fish" ]]; then
		UPDATE_FISH=1
	fi
	if [[ "${UPDATE_BASH}" == "0" && "${UPDATE_ZSH}" == "0" && "${UPDATE_FISH}" == "0" ]]; then
		UPDATE_BASH=1
		UPDATE_ZSH=1
		UPDATE_FISH=1
	fi
fi

WOULD_ADD_TO_PATH="false"
if [[ "${ADD_TO_PATH}" == "1" && "${NO_ADD_TO_PATH}" == "0" && "${PRINT_PATH_COMMAND}" == "0" ]]; then
	WOULD_ADD_TO_PATH="true"
fi

if [[ "${DRY_RUN}" == "1" ]]; then
	if [[ "${REQUIRE_CHECKSUM}" == "1" && -z "${SHA256}" ]]; then
		echo "error: DEVDIAG_REQUIRE_CHECKSUM=1 set but no checksum provided" >&2
		exit 1
	fi
	cat <<EOF
repo=${REPO}
requested_version=${REQUESTED_VERSION}
resolved_version=${RESOLVED_VERSION}
app_version=${APP_VERSION}
archive=${URL}
bin_dir=${TARGET_DIR}
install_path=${INSTALL_PATH}
metadata_path=${METADATA_PATH}
go=$(go version)
checksum=${SHA256:-none}
path_status=${PATH_STATUS}
would_add_to_path=${WOULD_ADD_TO_PATH}
shell_target=${SHELL_TARGET}
EOF
	exit 0
fi

# Print metadata info if exists before beginning build
read_metadata

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
		-ldflags "-s -w -X github.com/meedoomostafa/devdiag/internal/version.Version=${APP_VERSION}" \
		-o "${OUT}" ./cmd/devdiag
)

mkdir -p "${TARGET_DIR}"

NEW_PATH="${TARGET_DIR}/devdiag.new"
BACKUP_PATH="${TARGET_DIR}/devdiag.old"

BACKUP_CREATED=0
if [[ -f "${INSTALL_PATH}" ]]; then
	cp "${INSTALL_PATH}" "${BACKUP_PATH}"
	BACKUP_CREATED=1
fi

if ! cp "${OUT}" "${NEW_PATH}"; then
	echo "error: failed to copy new binary to ${NEW_PATH}" >&2
	exit 1
fi

if ! chmod 0755 "${NEW_PATH}"; then
	echo "error: failed to make ${NEW_PATH} executable" >&2
	exit 1
fi

if ! mv "${NEW_PATH}" "${INSTALL_PATH}"; then
	echo "error: failed to move ${NEW_PATH} to ${INSTALL_PATH}" >&2
	exit 1
fi

# Write installation metadata
write_metadata

# PATH integration
if [[ "${ADD_TO_PATH}" == "1" && "${PATH_STATUS}" == "not_on_path" ]]; then
	display_path="${TARGET_DIR}"
	if [[ "${TARGET_DIR}" == "${HOME}"* ]]; then
		display_path="\$HOME${TARGET_DIR#${HOME}}"
	fi

	if [[ "${UPDATE_BASH}" == "1" ]]; then
		bash_file="${HOME}/.bashrc"
		if [[ ! -f "${bash_file}" && -f "${HOME}/.profile" ]]; then
			bash_file="${HOME}/.profile"
		fi
		update_sh_profile "${bash_file}" "${display_path}"
	fi

	if [[ "${UPDATE_ZSH}" == "1" ]]; then
		update_sh_profile "${HOME}/.zshrc" "${display_path}"
	fi

	if [[ "${UPDATE_FISH}" == "1" ]]; then
		update_fish_profile "${HOME}/.config/fish/config.fish" "${display_path}"
	fi

	PATH_STATUS="added"
fi

# Print explicit install summary
echo "DevDiag installed successfully"
echo "version: ${RESOLVED_VERSION}"
echo "source_ref: ${VERSION}"
echo "binary: ${INSTALL_PATH}"
if [[ "${BACKUP_CREATED}" == "1" ]]; then
	echo "backup: ${BACKUP_PATH}"
fi
echo "metadata: ${METADATA_PATH}"
echo "path_status: ${PATH_STATUS}"

if [[ "${PRINT_PATH_COMMAND}" == "1" ]]; then
	print_path_command
fi

if [[ "${PATH_STATUS}" == "not_on_path" ]]; then
	echo "Add ${TARGET_DIR} to PATH to run devdiag from any shell." >&2
fi
