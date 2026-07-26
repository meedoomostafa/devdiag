#!/usr/bin/env bash
# Derive the version string stamped into runner-built devdiag binaries.
# Order: git describe (works in git checkouts) -> DEVDIAG_ACTION_REF (the ref
# consumers pinned; action paths are tarball extracts without .git) -> dev.
# Never github.sha: that is the consumer repository's commit, not this
# action's revision.

set -euo pipefail

APP_VERSION="$(git describe --tags --always 2>/dev/null || true)"
if [ -z "$APP_VERSION" ] && [ -n "${DEVDIAG_ACTION_REF:-}" ]; then
  APP_VERSION="${DEVDIAG_ACTION_REF#refs/tags/}"
fi
printf '%s\n' "${APP_VERSION:-dev}"
