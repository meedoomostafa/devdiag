#!/usr/bin/env bash
# shellcheck disable=SC2154

set -euo pipefail


# Ensure PATH includes RUNNER_TEMP/bin or RUNNER_TEMP/devdiag-bin just in case
if [ -n "${RUNNER_TEMP:-}" ]; then
  export PATH="${RUNNER_TEMP}/devdiag-bin:${RUNNER_TEMP}/bin:${PATH}"
fi

normalize_bool() {
  case "${1,,}" in
    true|1|yes) echo "true" ;;
    false|0|no) echo "false" ;;
    *) return 1 ;;
  esac
}

if ! CI_ENABLED=$(normalize_bool "${CI:-true}"); then
  echo "Error: ci input must be true or false"
  exit 2
fi
if ! SUMMARY_ENABLED=$(normalize_bool "${SUMMARY:-true}"); then
  echo "Error: summary input must be true or false"
  exit 2
fi
if ! FAIL_ON_FINDINGS_ENABLED=$(normalize_bool "${FAIL_ON_FINDINGS:-true}"); then
  echo "Error: fail-on-findings input must be true or false"
  exit 2
fi
if ! INCLUDE_HIDDEN_ENABLED=$(normalize_bool "${INCLUDE_HIDDEN:-false}"); then
  echo "Error: include-hidden input must be true or false"
  exit 2
fi
if ! SAVE_REPORT_ENABLED=$(normalize_bool "${SAVE_REPORT:-true}"); then
  echo "Error: save-report input must be true or false"
  exit 2
fi

normalize_fail_severity() {
  case "${1,,}" in
    off|info|low|medium|high|critical) echo "${1,,}" ;;
    *) return 1 ;;
  esac
}

if ! FAIL_SEVERITY_NORMALIZED=$(normalize_fail_severity "${FAIL_SEVERITY:-high}"); then
  echo "Error: fail-severity input must be one of: off, info, low, medium, high, critical"
  exit 2
fi

if [ "${FAIL_ON_FINDINGS_ENABLED}" = "false" ]; then
  EFFECTIVE_FAIL_SEVERITY="off"
else
  EFFECTIVE_FAIL_SEVERITY="${FAIL_SEVERITY_NORMALIZED}"
fi

if [ -n "${MASK_VALUES:-}" ]; then
  while IFS= read -r MASK_VALUE; do
    if [ -n "${MASK_VALUE}" ]; then
      echo "::add-mask::${MASK_VALUE}"
    fi
  done <<< "${MASK_VALUES}"
fi

PROFILE_ARGS=()
if [ -n "${PROFILE:-}" ]; then
  PROFILE_ARGS+=(--profile "${PROFILE}")
fi
RULE_PACK_ARGS=()
if [ -n "${RULE_PACK:-}" ]; then
  RULE_PACK_ARGS+=(--rule-pack "${RULE_PACK}")
fi
CI_ARGS=()
if [ "${CI_ENABLED}" = "true" ]; then
  CI_ARGS+=(--ci)
fi
HIDDEN_ARGS=()
if [ "${INCLUDE_HIDDEN_ENABLED}" = "true" ]; then
  HIDDEN_ARGS+=(--include-hidden)
fi

REPORT_DIR="${RUNNER_TEMP:-/tmp}/devdiag-artifacts"
REPORT_PATH="${REPORT_DIR}/devdiag-report.json"
mkdir -p "${REPORT_DIR}"

# Check if .devdiag existed beforehand
HAD_DEVDIAG=true
if [ ! -d "${PATH_ARG:-.}/.devdiag" ]; then
  HAD_DEVDIAG=false
fi

SCAN_ARGS=("--format" "${FORMAT:-github}" "--redact" "${REDACT:-default}" "--fail-severity" "${EFFECTIVE_FAIL_SEVERITY}")
if [ "${SAVE_REPORT_ENABLED}" = "true" ]; then
  SCAN_ARGS+=("--save-report")
fi
SCAN_ARGS+=("${PROFILE_ARGS[@]}" "${RULE_PACK_ARGS[@]}" "${CI_ARGS[@]}" "${HIDDEN_ARGS[@]}" -- "${PATH_ARG:-.}")

# Run devdiag scan ONCE
set +e
devdiag scan "${SCAN_ARGS[@]}"
SCAN_EXIT=$?
set -e

LATEST_REPORT=""
# Find the saved report and copy it to the deterministic REPORT_PATH
if [ "${SAVE_REPORT_ENABLED}" = "true" ] && [ -d "${PATH_ARG:-.}/.devdiag/runs" ]; then
  latest_mtime=0
  for rep in "${PATH_ARG:-.}"/.devdiag/runs/*/report.json; do
    if [ -f "$rep" ]; then
      mtime=$(stat -c %Y "$rep" 2>/dev/null || stat -f %m "$rep" 2>/dev/null || echo 0)
      if [ "$mtime" -gt "$latest_mtime" ]; then
        latest_mtime="$mtime"
        LATEST_REPORT="$rep"
      fi
    fi
  done

  if [ -n "$LATEST_REPORT" ] && [ -f "$LATEST_REPORT" ]; then
    echo "Copying report from ${LATEST_REPORT} to ${REPORT_PATH}" >&2
    cp "$LATEST_REPORT" "$REPORT_PATH"
  else
    echo "Warning: no saved report found under ${PATH_ARG:-.}/.devdiag/runs" >&2
  fi
fi



# Clean up .devdiag if it did not exist before scan
if [ "${HAD_DEVDIAG}" = "false" ] && [ -d "${PATH_ARG:-.}/.devdiag" ]; then
  rm -rf "${PATH_ARG:-.}/.devdiag"
fi

REPORT_UPLOADED="false"
FINAL_REPORT_PATH=""
if [ "${SAVE_REPORT_ENABLED}" = "true" ]; then
  if [ -f "$REPORT_PATH" ]; then
    REPORT_UPLOADED="true"
    FINAL_REPORT_PATH="$REPORT_PATH"
  fi
fi

SUMMARY_WRITTEN="false"
if [ "${SUMMARY:-true}" = "true" ] && [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### DevDiag scan"
    echo ""
    if [ "${REPORT_UPLOADED}" = "true" ]; then
      echo "- Report artifact: \`${ARTIFACT_NAME:-devdiag-report}\`"
      echo "- Report path: \`${FINAL_REPORT_PATH}\`"
    fi
    echo "- Scan exit: \`${SCAN_EXIT}\`"
  } >> "${GITHUB_STEP_SUMMARY}"
  SUMMARY_WRITTEN="true"
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "report-path=${FINAL_REPORT_PATH}" >> "${GITHUB_OUTPUT}"
  echo "summary-written=${SUMMARY_WRITTEN}" >> "${GITHUB_OUTPUT}"
  echo "scan-exit-code=${SCAN_EXIT}" >> "${GITHUB_OUTPUT}"
  echo "report-uploaded=${REPORT_UPLOADED}" >> "${GITHUB_OUTPUT}"
fi

# Handle fail-on-findings/fail-severity exit code check
# exit code 1 represents findings exist. If fail-on-findings is false, exit with 0.
if [ "$SCAN_EXIT" -eq 1 ] && [ "${FAIL_ON_FINDINGS_ENABLED}" = "false" ]; then
  exit 0
fi

exit "$SCAN_EXIT"
