package updater

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// checksumFor extracts the sha256 hex digest for assetName from a
// checksums.txt body (shasum format: "<hex>  <name>"). Duplicate entries
// with conflicting digests are rejected.
func checksumFor(checksums []byte, assetName string) (string, error) {
	var found string
	scanner := bufio.NewScanner(bytes.NewReader(checksums))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 {
			continue
		}
		digest, name := fields[0], strings.TrimPrefix(fields[1], "*")
		if name != assetName {
			continue
		}
		if len(digest) != 64 || !isHex(digest) {
			return "", fmt.Errorf("checksums.txt carries a malformed digest for %s", assetName)
		}
		if found != "" && found != digest {
			return "", fmt.Errorf("checksums.txt carries conflicting digests for %s", assetName)
		}
		found = digest
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read checksums.txt: %w", err)
	}
	if found == "" {
		return "", fmt.Errorf("%s is not present in the release checksums.txt", assetName)
	}
	return found, nil
}

func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

// verifySHA256 confirms data hashes to expectedHex.
func verifySHA256(data []byte, expectedHex string) error {
	sum := sha256.Sum256(data)
	if !strings.EqualFold(hex.EncodeToString(sum[:]), expectedHex) {
		return fmt.Errorf("sha256 mismatch: asset does not match the release checksums.txt")
	}
	return nil
}

// VerifyAttestation runs `gh attestation verify` against the downloaded
// asset. Verification is MANDATORY and fail-closed: a checksums.txt sitting
// next to the asset shares the same trust boundary as the asset itself, so
// only the signed SLSA provenance (bound to this repository's release
// workflow identity) defeats a release-edit-level compromise.
//
// The gh CLI is required; without it the update is refused (scripts/
// install.sh remains the manual path, which documents its own trust model).
func (o *Options) VerifyAttestation(assetPath string) error {
	ghBin := o.ghPath()
	if _, err := exec.LookPath(ghBin); err != nil {
		return fmt.Errorf("the GitHub CLI (gh) is required to verify release provenance and was not found on PATH; install gh or use scripts/install.sh")
	}
	args := []string{
		"attestation", "verify", assetPath,
		"--repo", o.repo(),
		"--signer-workflow", o.repo() + "/.github/workflows/release.yml",
	}
	// Bounded like every other network step: a stalled gh (Sigstore fetch
	// hang, credential prompt) must not block the updater forever.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, ghBin, args...)
	cmd.Env = os.Environ()
	cmd.Stdin = nil
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	start := time.Now()
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(out.String())
		if len(msg) > 2000 {
			msg = msg[:2000]
		}
		return fmt.Errorf("provenance attestation verification FAILED after %s; refusing to update.\n%s", time.Since(start).Round(time.Millisecond), msg)
	}
	return nil
}
