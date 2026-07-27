package updater

import (
	"fmt"
	"os"
)

// Progress receives human-readable step notifications during Apply.
type Progress func(step string)

// Result describes a completed update.
type Result struct {
	Tag        string
	AssetName  string
	TargetPath string
	BackupPath string
}

// Apply performs the full verified update to rel for targetPath:
// download -> mandatory checksum -> mandatory provenance attestation ->
// path-safe extraction -> atomic swap. Any failure leaves the installed
// binary untouched.
func (o *Options) Apply(rel *Release, targetPath string, progress Progress) (*Result, error) {
	if progress == nil {
		progress = func(string) {}
	}

	assetName, err := AssetName(rel.TagName)
	if err != nil {
		return nil, err
	}
	if _, ok := rel.Assets["checksums.txt"]; !ok {
		return nil, fmt.Errorf("release %s publishes no checksums.txt; it predates the verified release pipeline. Reinstall with scripts/install.sh instead", rel.TagName)
	}

	progress("downloading " + assetName)
	asset, err := o.fetch(o.assetURL(rel, assetName), "application/octet-stream", maxAssetBytes)
	if err != nil {
		return nil, fmt.Errorf("download release asset: %w", err)
	}

	progress("verifying checksum")
	checksums, err := o.fetch(o.assetURL(rel, "checksums.txt"), "application/octet-stream", maxChecksumsBytes)
	if err != nil {
		return nil, fmt.Errorf("download release checksums.txt (updates require the verified release pipeline; for source installs use scripts/install.sh): %w", err)
	}
	expected, err := checksumFor(checksums, assetName)
	if err != nil {
		return nil, err
	}
	if err := verifySHA256(asset, expected); err != nil {
		return nil, err
	}

	tmpDir, err := os.MkdirTemp("", "devdiag-update-*")
	if err != nil {
		return nil, fmt.Errorf("create update staging directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	assetPath := tmpDir + "/" + assetName
	if err := os.WriteFile(assetPath, asset, 0o600); err != nil {
		return nil, fmt.Errorf("stage release asset: %w", err)
	}

	progress("verifying provenance attestation")
	if err := o.VerifyAttestation(assetPath); err != nil {
		return nil, err
	}

	progress("extracting binary")
	binPath, err := ExtractBinary(asset, tmpDir)
	if err != nil {
		return nil, err
	}

	progress("swapping binary into place")
	if err := SwapBinary(binPath, targetPath); err != nil {
		return nil, err
	}

	return &Result{
		Tag:        rel.TagName,
		AssetName:  assetName,
		TargetPath: targetPath,
		BackupPath: targetPath + ".old",
	}, nil
}
