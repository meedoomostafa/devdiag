package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/exitcode"
	"github.com/meedoomostafa/devdiag/internal/updater"
	"github.com/meedoomostafa/devdiag/internal/version"
)

var updateDryRun bool

type InstallMetadata struct {
	SchemaVersion    string `json:"schema_version"`
	Repo             string `json:"repo"`
	SourceRef        string `json:"source_ref"`
	ResolvedVersion  string `json:"resolved_version"`
	InstallDir       string `json:"install_dir"`
	BinaryPath       string `json:"binary_path"`
	InstalledAt      string `json:"installed_at"`
	InstallMethod    string `json:"install_method"`
	ArchiveURL       string `json:"archive_url"`
	ChecksumRequired bool   `json:"checksum_required"`
	ChecksumProvided bool   `json:"checksum_provided"`
}

var metadataPathOverride string

func getMetadataPath() string {
	if metadataPathOverride != "" {
		return metadataPathOverride
	}
	xdg := os.Getenv("XDG_CONFIG_HOME")
	if xdg != "" {
		return filepath.Join(xdg, "devdiag", "install.json")
	}
	home := os.Getenv("HOME")
	if home == "" {
		if h, err := os.UserHomeDir(); err == nil {
			return filepath.Join(h, ".config", "devdiag", "install.json")
		}
		return ""
	}
	return filepath.Join(home, ".config", "devdiag", "install.json")
}

// updaterOptions builds updater options. The API/download override env vars
// are test seams: the updater itself refuses to attach credentials to
// non-github, non-loopback hosts, so a hostile override cannot exfiltrate
// GITHUB_TOKEN (it previously could).
func updaterOptions(repo string) *updater.Options {
	return &updater.Options{
		Repo:         repo,
		APIBase:      os.Getenv("DEVDIAG_GITHUB_API_BASE_URL"),
		DownloadBase: os.Getenv("DEVDIAG_DOWNLOAD_BASE_URL"),
		GHPath:       os.Getenv("DEVDIAG_GH_PATH"),
	}
}

func redactUpdateError(err error) string {
	if err == nil {
		return ""
	}
	errMsg := err.Error()
	if token := os.Getenv("GITHUB_TOKEN"); token != "" {
		errMsg = strings.ReplaceAll(errMsg, token, "<redacted>")
	}
	if token := os.Getenv("GH_TOKEN"); token != "" {
		errMsg = strings.ReplaceAll(errMsg, token, "<redacted>")
	}
	return errMsg
}

func normalizeVersion(v string) string {
	v = strings.TrimPrefix(v, "refs/tags/")
	v = strings.TrimPrefix(v, "refs/heads/")
	v = strings.TrimPrefix(v, "v")
	return v
}

func compareVersions(a, b string) int {
	aParts := strings.Split(normalizeVersion(a), ".")
	bParts := strings.Split(normalizeVersion(b), ".")
	maxParts := len(aParts)
	if len(bParts) > maxParts {
		maxParts = len(bParts)
	}
	for i := 0; i < maxParts; i++ {
		var aNum, bNum int
		if i < len(aParts) {
			aNum, _ = strconv.Atoi(aParts[i])
		}
		if i < len(bParts) {
			bNum, _ = strconv.Atoi(bParts[i])
		}
		if aNum > bNum {
			return 1
		}
		if aNum < bNum {
			return -1
		}
	}
	return 0
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update DevDiag to the latest version",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Read install metadata
		metadataPath := getMetadataPath()
		var metadata InstallMetadata
		var hasMetadata bool
		var malformedMetadata bool

		if metadataPath != "" {
			if data, err := os.ReadFile(metadataPath); err == nil {
				if err := json.Unmarshal(data, &metadata); err == nil {
					hasMetadata = true
				} else {
					malformedMetadata = true
				}
			}
		}

		repo := "meedoomostafa/devdiag"
		if hasMetadata && metadata.Repo != "" {
			repo = metadata.Repo
		}

		opts := updaterOptions(repo)
		rel, err := opts.LatestRelease()
		if err != nil {
			return fmt.Errorf("failed to resolve latest DevDiag release: %s", redactUpdateError(err))
		}
		latestVersionRaw := rel.TagName

		latestVersion := normalizeVersion(latestVersionRaw)
		currentVersion := normalizeVersion(version.Version)
		currentCompare := compareVersions(currentVersion, latestVersion)

		fmt.Fprintln(cmd.OutOrStdout(), "DevDiag update plan")
		fmt.Fprintf(cmd.OutOrStdout(), "current_version: %s\n", currentVersion)
		fmt.Fprintf(cmd.OutOrStdout(), "latest_version: %s\n", latestVersion)

		if hasMetadata {
			fmt.Fprintf(cmd.OutOrStdout(), "installed_binary: %s\n", metadata.BinaryPath)
			fmt.Fprintf(cmd.OutOrStdout(), "install_method: %s\n", metadata.InstallMethod)
			if currentCompare >= 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "action: already_up_to_date")
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), "action: update_available")
			}
		} else if malformedMetadata {
			fmt.Fprintln(cmd.OutOrStdout(), "action: metadata_malformed")
			fmt.Fprintln(cmd.OutOrStdout(), "hint: reinstall with scripts/install.sh to create metadata")
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "action: metadata_missing")
			fmt.Fprintln(cmd.OutOrStdout(), "hint: reinstall with scripts/install.sh to create metadata")
		}

		if updateDryRun {
			return nil
		}

		if currentCompare >= 0 {
			return nil
		}

		if malformedMetadata {
			return exitCodeError{
				code:    exitcode.InvalidInput,
				message: "cannot apply update because install metadata is malformed; reinstall with scripts/install.sh",
			}
		}

		// Resolve the binary to replace: install metadata first, the
		// running executable as fallback. Both must agree when both exist,
		// otherwise the metadata is stale and mutation is unsafe.
		targetPath := ""
		if hasMetadata && metadata.BinaryPath != "" {
			targetPath = metadata.BinaryPath
		}
		if exe, exeErr := os.Executable(); exeErr == nil {
			resolved, rerr := filepath.EvalSymlinks(exe)
			if rerr == nil {
				exe = resolved
			}
			if targetPath == "" {
				targetPath = exe
			}
		}
		if targetPath == "" {
			return exitCodeError{
				code:    exitcode.InvalidInput,
				message: "cannot determine the installed binary path; reinstall with scripts/install.sh",
			}
		}

		fmt.Fprintln(cmd.OutOrStdout(), "action: applying_update")

		res, err := opts.Apply(rel, targetPath, func(step string) {
			fmt.Fprintf(cmd.OutOrStdout(), "step: %s\n", step)
		})
		if err != nil {
			return fmt.Errorf("update refused: %s", redactUpdateError(err))
		}

		// Refresh install metadata after the successful swap. A metadata
		// write failure is partial success: the binary IS updated.
		if metaErr := writeUpdatedMetadata(metadataPath, metadata, hasMetadata, repo, res); metaErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: binary updated but metadata refresh failed: %v\n", metaErr)
		}

		fmt.Fprintf(cmd.OutOrStdout(), "backup: %s\n", res.BackupPath)
		fmt.Fprintln(cmd.OutOrStdout(), "action: updated")

		return nil
	},
}

// writeUpdatedMetadata refreshes install.json after a successful update.
// The write is atomic (temp file + rename) so a crash cannot leave a
// truncated metadata file.
func writeUpdatedMetadata(metadataPath string, old InstallMetadata, hadMetadata bool, repo string, res *updater.Result) error {
	if metadataPath == "" {
		return fmt.Errorf("no metadata path resolvable")
	}
	meta := old
	if !hadMetadata {
		meta = InstallMetadata{SchemaVersion: "1"}
	}
	meta.Repo = repo
	meta.SourceRef = res.Tag
	meta.ResolvedVersion = normalizeVersion(res.Tag)
	meta.InstallDir = filepath.Dir(res.TargetPath)
	meta.BinaryPath = res.TargetPath
	meta.InstalledAt = time.Now().UTC().Format(time.RFC3339)
	meta.InstallMethod = "release-binary"
	meta.ArchiveURL = res.AssetName
	meta.ChecksumRequired = true
	meta.ChecksumProvided = true

	if err := os.MkdirAll(filepath.Dir(metadataPath), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	tmp := metadataPath + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, metadataPath)
}

func init() {
	updateCmd.Flags().BoolVar(&updateDryRun, "dry-run", false, "Preview the update plan")

	updateCmd.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		return exitCodeError{
			code:    exitcode.InvalidInput,
			message: err.Error(),
		}
	})

	rootCmd.AddCommand(updateCmd)
}
