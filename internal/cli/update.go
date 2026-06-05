package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/meedoomostafa/devdiag/internal/exitcode"
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

type GitHubRelease struct {
	TagName string `json:"tag_name"`
}

var metadataPathOverride string
var gitHubAPIBase = "https://api.github.com"

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

func getGitHubAPIBase() string {
	if url := os.Getenv("DEVDIAG_GITHUB_API_BASE_URL"); url != "" {
		return url
	}
	return gitHubAPIBase
}

func fetchLatestVersion(repo string) (string, error) {
	if repo == "" {
		repo = "meedoomostafa/devdiag"
	}
	apiURL := fmt.Sprintf("%s/repos/%s/releases/latest", getGitHubAPIBase(), repo)
	
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "devdiag-updater")
	
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	if token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	}
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}
	
	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}
	return release.TagName, nil
}

func normalizeVersion(v string) string {
	v = strings.TrimPrefix(v, "refs/tags/")
	v = strings.TrimPrefix(v, "refs/heads/")
	v = strings.TrimPrefix(v, "v")
	return v
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update DevDiag to the latest version (dry-run only)",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if !updateDryRun {
			return exitCodeError{
				code:    exitcode.InvalidInput,
				message: "devdiag update apply is not implemented yet; use install.sh to update.",
			}
		}

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

		latestVersionRaw, err := fetchLatestVersion(repo)
		if err != nil {
			errMsg := err.Error()
			if token := os.Getenv("GITHUB_TOKEN"); token != "" {
				errMsg = strings.ReplaceAll(errMsg, token, "<redacted>")
			}
			if token := os.Getenv("GH_TOKEN"); token != "" {
				errMsg = strings.ReplaceAll(errMsg, token, "<redacted>")
			}
			return fmt.Errorf("failed to resolve latest DevDiag release: %s", errMsg)
		}

		latestVersion := normalizeVersion(latestVersionRaw)
		currentVersion := normalizeVersion(version.Version)

		fmt.Fprintln(cmd.OutOrStdout(), "DevDiag update plan")
		fmt.Fprintf(cmd.OutOrStdout(), "current_version: %s\n", currentVersion)
		fmt.Fprintf(cmd.OutOrStdout(), "latest_version: %s\n", latestVersion)

		if hasMetadata {
			fmt.Fprintf(cmd.OutOrStdout(), "installed_binary: %s\n", metadata.BinaryPath)
			fmt.Fprintf(cmd.OutOrStdout(), "install_method: %s\n", metadata.InstallMethod)
			if currentVersion == latestVersion {
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

		return nil
	},
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
