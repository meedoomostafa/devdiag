package updater

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
)

// Release describes the release selected for the update.
type Release struct {
	TagName string
	// Assets maps asset names to their browser download URLs.
	Assets map[string]string
}

type githubRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// LatestRelease resolves the latest published release and its asset list.
func (o *Options) LatestRelease() (*Release, error) {
	data, err := o.fetch(
		fmt.Sprintf("%s/repos/%s/releases/latest", o.apiBase(), o.repo()),
		"application/vnd.github+json",
		maxChecksumsBytes,
	)
	if err != nil {
		return nil, err
	}
	var gr githubRelease
	if err := json.Unmarshal(data, &gr); err != nil {
		return nil, fmt.Errorf("parse release response: %w", err)
	}
	if gr.TagName == "" {
		return nil, fmt.Errorf("release response carried no tag_name")
	}
	rel := &Release{TagName: gr.TagName, Assets: make(map[string]string, len(gr.Assets))}
	for _, a := range gr.Assets {
		rel.Assets[a.Name] = a.BrowserDownloadURL
	}
	return rel, nil
}

// AssetName returns the release archive name for this platform, or an error
// on unsupported architectures.
func AssetName(tag string) (string, error) {
	arch := runtime.GOARCH
	switch arch {
	case "amd64", "arm64":
	default:
		return "", fmt.Errorf("no prebuilt DevDiag release for %s/%s; install from source with scripts/install.sh", runtime.GOOS, arch)
	}
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("no prebuilt DevDiag release for %s/%s; install from source with scripts/install.sh", runtime.GOOS, arch)
	}
	return fmt.Sprintf("devdiag_%s_linux_%s.tar.gz", strings.TrimPrefix(tag, "v"), arch), nil
}

// assetURL resolves the download URL for name, preferring the API-provided
// asset URL and falling back to the conventional release download path.
func (o *Options) assetURL(rel *Release, name string) string {
	if u, ok := rel.Assets[name]; ok && u != "" && o.DownloadBase == "" {
		return u
	}
	return fmt.Sprintf("%s/%s/releases/download/%s/%s", o.downloadBase(), o.repo(), rel.TagName, name)
}
