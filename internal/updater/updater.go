// Package updater implements the in-binary self-update flow: resolve the
// latest release, download the platform binary asset, verify it against the
// release checksums.txt (mandatory) and its SLSA provenance attestation via
// the gh CLI (mandatory, fail-closed), then atomically swap the installed
// binary. It never executes downloaded scripts.
package updater

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// DefaultRepo is the canonical DevDiag repository.
const DefaultRepo = "meedoomostafa/devdiag"

// maxAssetBytes caps release-asset downloads. Release archives are ~10MB;
// anything past this is malformed or hostile.
const maxAssetBytes = 256 << 20

// maxChecksumsBytes caps the checksums.txt download.
const maxChecksumsBytes = 1 << 20

// Options configures an update run.
type Options struct {
	// Repo is the owner/name GitHub repository. Defaults to DefaultRepo.
	Repo string
	// APIBase overrides the GitHub API base URL. Test seam: non-loopback
	// overrides never receive credentials (see authHeaderAllowed).
	APIBase string
	// DownloadBase overrides the release asset download base URL
	// (https://github.com by default). Test seam with the same credential
	// restriction as APIBase.
	DownloadBase string
	// GHPath overrides the gh CLI binary used for attestation
	// verification. Test seam; defaults to "gh" resolved via PATH.
	GHPath string
	// HTTPClient overrides the HTTP client. Defaults to a 30s-timeout client.
	HTTPClient *http.Client
}

func (o *Options) repo() string {
	if o.Repo != "" {
		return o.Repo
	}
	return DefaultRepo
}

func (o *Options) apiBase() string {
	if o.APIBase != "" {
		return strings.TrimSuffix(o.APIBase, "/")
	}
	return "https://api.github.com"
}

func (o *Options) downloadBase() string {
	if o.DownloadBase != "" {
		return strings.TrimSuffix(o.DownloadBase, "/")
	}
	return "https://github.com"
}

func (o *Options) client() *http.Client {
	if o.HTTPClient != nil {
		return o.HTTPClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

// authHeaderAllowed reports whether GITHUB_TOKEN/GH_TOKEN may be attached to
// requests against base. Credentials only ever go to github.com properties
// or loopback (test servers); an environment override pointing anywhere else
// must not receive the caller's token.
func authHeaderAllowed(base string) bool {
	u, err := url.Parse(base)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "api.github.com" || host == "github.com" || strings.HasSuffix(host, ".github.com") {
		return true
	}
	return host == "127.0.0.1" || host == "::1" || host == "localhost"
}

func (o *Options) newRequest(method, rawURL, accept string) (*http.Request, error) {
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	req.Header.Set("User-Agent", "devdiag-updater")
	if authHeaderAllowed(rawURL) {
		token := os.Getenv("GITHUB_TOKEN")
		if token == "" {
			token = os.Getenv("GH_TOKEN")
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	return req, nil
}

// fetch downloads rawURL, enforcing an HTTP 200 response and a byte cap.
func (o *Options) fetch(rawURL, accept string, capBytes int64) ([]byte, error) {
	req, err := o.newRequest(http.MethodGet, rawURL, accept)
	if err != nil {
		return nil, err
	}
	resp, err := o.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned status %d", redactURL(rawURL), resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, capBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > capBytes {
		return nil, fmt.Errorf("GET %s exceeded the %d byte cap", redactURL(rawURL), capBytes)
	}
	return data, nil
}

// redactURL strips query strings and userinfo from URLs before they appear
// in error text.
func redactURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "<unparsable-url>"
	}
	u.RawQuery = ""
	u.User = nil
	return u.String()
}
