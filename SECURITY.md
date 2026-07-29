# Security Policy

DevDiag is a diagnostic tool that reads environment and repository state and
produces redacted reports. Its most security-sensitive surfaces are the
redaction pipeline (secrets must never reach reports, capsules, or CI logs),
the GitHub Action, and the install/update flow.

## Supported versions

Only the latest release receives security fixes. Pre-1.0, there is no
long-term support branch; upgrade to the newest `v0.x` release.

## Reporting a vulnerability

Please **do not open a public issue for security reports**.

Use [GitHub private vulnerability reporting](https://github.com/meedoomostafa/devdiag/security/advisories/new)
to file a report. You can expect:

- Acknowledgment within 72 hours
- An assessment and remediation plan within 7 days for confirmed issues
- Credit in the release notes (unless you prefer otherwise)

Reports of redaction bypasses (any way a real secret value can reach a
report, capsule, artifact, log line, or workflow annotation at
`--redact default` or `strict`) are treated as the highest severity.

## Release trust model

- Release binaries are built by the public `release.yml` workflow from tags
  reachable from `main`; every build artifact (binary archives and SBOMs) is
  listed in `checksums.txt` and covered by a signed SLSA build provenance
  attestation. The provenance copy described below is produced after
  attestation and is therefore deliberately not part of that claim:

  ```bash
  sha256sum -c --ignore-missing checksums.txt
  gh attestation verify --owner meedoomostafa <asset>
  ```

- Each release also carries a `devdiag_<version>.intoto.jsonl` asset: an
  **informational copy** of the provenance bundle, published for offline
  inspection and for tools that scan release assets. It is not the
  authority. Anyone with release-edit rights could replace that file,
  whereas the attestation stored in GitHub's attestation API cannot be
  swapped that way — so `gh attestation verify` (which queries the API)
  remains the authoritative check, and it is what `devdiag update`
  enforces.

- `install.sh` verifies release binaries against `checksums.txt` and fails
  closed; source builds only occur for branches/SHAs and pre-pipeline
  releases.
- The GitHub Action should be pinned to the `v0` major tag (moved only after
  a release fully publishes) or a full commit SHA.

## Self-update trust model

`devdiag update` never executes downloaded scripts. It downloads the
platform binary asset, verifies it against the release `checksums.txt`
(mandatory) and its signed SLSA provenance attestation via the GitHub CLI
(mandatory, fail-closed — no `gh` on PATH means the update is refused), then
swaps the binary atomically with a `devdiag.old` rollback backup. Releases
without pipeline assets (v0.4.0 and earlier) are refused with reinstall
guidance.

## Known limitations

- Redaction is pattern- and source-based; it is defense-in-depth, not a
  license to feed production secrets into scanned fixtures.
