package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// --- fixtures ---------------------------------------------------------

type tarEntry struct {
	name     string
	body     []byte
	typeflag byte
	linkname string
	size     int64 // overrides len(body) when non-zero
}

func makeTarGz(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		tf := e.typeflag
		if tf == 0 {
			tf = tar.TypeReg
		}
		size := int64(len(e.body))
		if e.size != 0 {
			size = e.size
		}
		hdr := &tar.Header{Name: e.name, Mode: 0o755, Size: size, Typeflag: tf, Linkname: e.linkname}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if tf == tar.TypeReg && len(e.body) > 0 {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sha256hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// fakeGH writes a stub gh binary whose exit code is controlled by content.
func fakeGH(t *testing.T, exitCode int) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "gh")
	script := fmt.Sprintf("#!/bin/sh\necho fake-gh \"$@\"\nexit %d\n", exitCode)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// releaseServer serves a fake GitHub API + asset download endpoint.
func releaseServer(t *testing.T, tag string, assets map[string][]byte) (*httptest.Server, *Options) {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		names := make([]string, 0, len(assets))
		for n := range assets {
			names = append(names, fmt.Sprintf(`{"name":%q,"browser_download_url":"%s/dl/%s"}`, n, srv.URL, n))
		}
		fmt.Fprintf(w, `{"tag_name":%q,"assets":[%s]}`, tag, strings.Join(names, ","))
	})
	mux.HandleFunc("/dl/", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/dl/")
		body, ok := assets[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Write(body)
	})

	opts := &Options{
		APIBase:      srv.URL,
		DownloadBase: "", // API-provided asset URLs point at srv
		GHPath:       fakeGH(t, 0),
	}
	return srv, opts
}

func platformAsset(t *testing.T, tag string) (string, []byte) {
	t.Helper()
	name, err := AssetName(tag)
	if err != nil {
		t.Skipf("unsupported test platform: %v", err)
	}
	binary := []byte("#!/bin/sh\necho updated-devdiag " + tag + "\n")
	archive := makeTarGz(t, []tarEntry{
		{name: "devdiag", body: binary},
		{name: "LICENSE", body: []byte("MIT")},
	})
	return name, archive
}

// --- checksum parsing --------------------------------------------------

func TestChecksumFor(t *testing.T) {
	digest := strings.Repeat("ab", 32)
	cases := []struct {
		name      string
		checksums string
		wantErr   string
	}{
		{"found", digest + "  devdiag_1_linux_amd64.tar.gz\n", ""},
		{"binary-mode marker", digest + "  *devdiag_1_linux_amd64.tar.gz\n", ""},
		{"missing", digest + "  other.tar.gz\n", "not present"},
		{"malformed digest", "zz  devdiag_1_linux_amd64.tar.gz\n", "malformed"},
		{"conflicting duplicates", digest + "  devdiag_1_linux_amd64.tar.gz\n" + strings.Repeat("cd", 32) + "  devdiag_1_linux_amd64.tar.gz\n", "conflicting"},
		{"consistent duplicates ok", digest + "  devdiag_1_linux_amd64.tar.gz\n" + digest + "  devdiag_1_linux_amd64.tar.gz\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := checksumFor([]byte(tc.checksums), "devdiag_1_linux_amd64.tar.gz")
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got != digest {
					t.Fatalf("digest = %q, want %q", got, digest)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want contains %q", err, tc.wantErr)
			}
		})
	}
}

// --- extraction hardening ----------------------------------------------

func TestExtractBinary_RejectsHostileArchives(t *testing.T) {
	bin := []byte("binary")
	cases := []struct {
		name    string
		entries []tarEntry
		wantErr string
	}{
		{"traversal", []tarEntry{{name: "../devdiag", body: bin}}, "escapes"},
		{"absolute", []tarEntry{{name: "/usr/bin/devdiag", body: bin}}, "escapes"},
		{"symlink", []tarEntry{{name: "devdiag", typeflag: tar.TypeSymlink, linkname: "/bin/sh"}}, "link"},
		{"hardlink", []tarEntry{{name: "devdiag", typeflag: tar.TypeLink, linkname: "/bin/sh"}}, "link"},
		{"device", []tarEntry{{name: "devdiag", typeflag: tar.TypeChar}}, "non-regular"},
		{"duplicate", []tarEntry{{name: "devdiag", body: bin}, {name: "sub/devdiag", body: bin}}, "more than one"},
		{"missing", []tarEntry{{name: "LICENSE", body: bin}}, "does not contain"},
		{"empty entry", []tarEntry{{name: "devdiag", size: 0}}, "implausible size"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ExtractBinary(makeTarGz(t, tc.entries), t.TempDir())
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want contains %q", err, tc.wantErr)
			}
		})
	}
}

func TestExtractBinary_NotGzip(t *testing.T) {
	if _, err := ExtractBinary([]byte("plain text"), t.TempDir()); err == nil || !strings.Contains(err.Error(), "gzip") {
		t.Fatalf("error = %v, want gzip error", err)
	}
}

func TestExtractBinary_Valid(t *testing.T) {
	bin := []byte("the-binary")
	path, err := ExtractBinary(makeTarGz(t, []tarEntry{
		{name: "LICENSE", body: []byte("MIT")},
		{name: "devdiag", body: bin},
		{name: "README.md", body: []byte("docs")},
	}), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, bin) {
		t.Fatalf("extracted binary content mismatch")
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm()&0o111 == 0 {
		t.Fatalf("extracted binary not executable: %v", fi.Mode())
	}
}

// --- swap semantics ------------------------------------------------------

func TestSwapBinary_ReplacesAndBacksUp(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "devdiag")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	newBin := filepath.Join(t.TempDir(), "new")
	if err := os.WriteFile(newBin, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := SwapBinary(newBin, target); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(target)
	if string(got) != "new" {
		t.Fatalf("target = %q, want new", got)
	}
	backup, err := os.ReadFile(target + ".old")
	if err != nil || string(backup) != "old" {
		t.Fatalf("backup = %q err=%v, want old", backup, err)
	}
}

func TestSwapBinary_RefusesSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real-devdiag")
	if err := os.WriteFile(real, []byte("real"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "devdiag")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	newBin := filepath.Join(t.TempDir(), "new")
	os.WriteFile(newBin, []byte("new"), 0o755)
	if err := SwapBinary(newBin, link); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("error = %v, want symlink refusal", err)
	}
	data, _ := os.ReadFile(real)
	if string(data) != "real" {
		t.Fatalf("real binary was modified: %q", data)
	}
}

func TestSwapBinary_UnwritableDirRefused(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("mode bits not enforced for root")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "devdiag")
	os.WriteFile(target, []byte("old"), 0o755)
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	newBin := filepath.Join(t.TempDir(), "new")
	os.WriteFile(newBin, []byte("new"), 0o755)
	if err := SwapBinary(newBin, target); err == nil || !strings.Contains(err.Error(), "cannot write") {
		t.Fatalf("error = %v, want unwritable refusal", err)
	}
}

// --- credential scoping ---------------------------------------------------

func TestAuthHeaderAllowed(t *testing.T) {
	cases := map[string]bool{
		"https://api.github.com/repos/x":    true,
		"https://github.com/x/releases":     true,
		"https://objects.github.com/asset":  true,
		"http://127.0.0.1:8080/repos/x":     true,
		"http://localhost:9999/x":           true,
		"https://evil.example.com/repos/x":  false,
		"https://api.github.com.evil.com/x": false,
		"https://fakegithub.com/x":          false,
	}
	for base, want := range cases {
		if got := authHeaderAllowed(base); got != want {
			t.Errorf("authHeaderAllowed(%q) = %v, want %v", base, got, want)
		}
	}
}

func TestFetch_NoCredentialsToForeignHosts(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte("ok"))
	}))
	defer srv.Close()
	t.Setenv("GITHUB_TOKEN", "supersecret-token")

	o := &Options{}
	// httptest URLs are loopback, so credentials ARE allowed there; verify
	// the loopback path first (test seam behavior).
	if _, err := o.fetch(srv.URL, "", 1024); err != nil {
		t.Fatal(err)
	}
	if gotAuth == "" {
		t.Fatal("loopback test server should receive credentials (test seam)")
	}
	// A foreign, non-github host must never see the token: simulate by
	// asserting the header-attachment decision function directly since we
	// cannot safely dial foreign hosts in tests.
	if authHeaderAllowed("https://mirror.example.com/devdiag") {
		t.Fatal("foreign host must not receive credentials")
	}
}

// --- end-to-end Apply -------------------------------------------------------

func TestApply_HappyPath(t *testing.T) {
	tag := "v9.9.9"
	assetName, archive := platformAsset(t, tag)
	assets := map[string][]byte{
		assetName:       archive,
		"checksums.txt": []byte(sha256hex(archive) + "  " + assetName + "\n"),
	}
	_, opts := releaseServer(t, tag, assets)

	rel, err := opts.LatestRelease()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "devdiag")
	os.WriteFile(target, []byte("old"), 0o755)

	var steps []string
	res, err := opts.Apply(rel, target, func(s string) { steps = append(steps, s) })
	if err != nil {
		t.Fatal(err)
	}
	if res.Tag != tag {
		t.Fatalf("tag = %s, want %s", res.Tag, tag)
	}
	data, _ := os.ReadFile(target)
	if !strings.Contains(string(data), "updated-devdiag "+tag) {
		t.Fatalf("target content = %q, want updated binary", data)
	}
	if backup, _ := os.ReadFile(target + ".old"); string(backup) != "old" {
		t.Fatalf("backup missing or wrong: %q", backup)
	}
	joined := strings.Join(steps, "|")
	for _, want := range []string{"checksum", "provenance", "swap"} {
		if !strings.Contains(joined, want) {
			t.Errorf("progress steps missing %q: %v", want, steps)
		}
	}
}

func TestApply_ChecksumMismatchRefused(t *testing.T) {
	tag := "v9.9.9"
	assetName, archive := platformAsset(t, tag)
	assets := map[string][]byte{
		assetName:       archive,
		"checksums.txt": []byte(strings.Repeat("00", 32) + "  " + assetName + "\n"),
	}
	_, opts := releaseServer(t, tag, assets)
	rel, _ := opts.LatestRelease()
	target := filepath.Join(t.TempDir(), "devdiag")
	os.WriteFile(target, []byte("old"), 0o755)

	_, err := opts.Apply(rel, target, nil)
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("error = %v, want sha256 mismatch", err)
	}
	if data, _ := os.ReadFile(target); string(data) != "old" {
		t.Fatalf("target modified on refusal: %q", data)
	}
}

func TestApply_MissingChecksumsRefused(t *testing.T) {
	tag := "v9.9.9"
	assetName, archive := platformAsset(t, tag)
	assets := map[string][]byte{assetName: archive}
	_, opts := releaseServer(t, tag, assets)
	rel, _ := opts.LatestRelease()
	target := filepath.Join(t.TempDir(), "devdiag")
	os.WriteFile(target, []byte("old"), 0o755)

	_, err := opts.Apply(rel, target, nil)
	if err == nil || !strings.Contains(err.Error(), "checksums.txt") {
		t.Fatalf("error = %v, want checksums refusal", err)
	}
}

func TestApply_AttestationFailureRefused(t *testing.T) {
	tag := "v9.9.9"
	assetName, archive := platformAsset(t, tag)
	assets := map[string][]byte{
		assetName:       archive,
		"checksums.txt": []byte(sha256hex(archive) + "  " + assetName + "\n"),
	}
	_, opts := releaseServer(t, tag, assets)
	opts.GHPath = fakeGH(t, 1) // gh exits nonzero -> verification failed
	rel, _ := opts.LatestRelease()
	target := filepath.Join(t.TempDir(), "devdiag")
	os.WriteFile(target, []byte("old"), 0o755)

	_, err := opts.Apply(rel, target, nil)
	if err == nil || !strings.Contains(err.Error(), "attestation verification FAILED") {
		t.Fatalf("error = %v, want attestation refusal", err)
	}
	if data, _ := os.ReadFile(target); string(data) != "old" {
		t.Fatalf("target modified on refusal: %q", data)
	}
}

func TestApply_MissingGHRefused(t *testing.T) {
	tag := "v9.9.9"
	assetName, archive := platformAsset(t, tag)
	assets := map[string][]byte{
		assetName:       archive,
		"checksums.txt": []byte(sha256hex(archive) + "  " + assetName + "\n"),
	}
	_, opts := releaseServer(t, tag, assets)
	opts.GHPath = "/nonexistent/gh-cli-binary"
	rel, _ := opts.LatestRelease()
	target := filepath.Join(t.TempDir(), "devdiag")
	os.WriteFile(target, []byte("old"), 0o755)

	_, err := opts.Apply(rel, target, nil)
	if err == nil || !strings.Contains(err.Error(), "gh") {
		t.Fatalf("error = %v, want missing-gh refusal", err)
	}
}

func TestApply_AssetDownloadFailureRefused(t *testing.T) {
	tag := "v9.9.9"
	assetName, _ := platformAsset(t, tag)
	// API lists the asset, but downloads 404.
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"tag_name":%q,"assets":[{"name":%q,"browser_download_url":"%s/dl/gone"},{"name":"checksums.txt","browser_download_url":"%s/dl/gone2"}]}`, tag, assetName, srv.URL, srv.URL)
	})
	opts := &Options{APIBase: srv.URL, GHPath: fakeGH(t, 0)}
	rel, err := opts.LatestRelease()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "devdiag")
	os.WriteFile(target, []byte("old"), 0o755)
	if _, err := opts.Apply(rel, target, nil); err == nil {
		t.Fatal("expected download failure to refuse the update")
	}
}

func TestAssetName(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-only naming")
	}
	name, err := AssetName("v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	want := "devdiag_1.2.3_linux_" + runtime.GOARCH + ".tar.gz"
	if name != want {
		t.Fatalf("AssetName = %q, want %q", name, want)
	}
}

func TestLatestRelease_BadResponses(t *testing.T) {
	cases := []struct {
		name string
		body string
		code int
	}{
		{"non-200", "", http.StatusForbidden},
		{"invalid json", "not-json", http.StatusOK},
		{"empty tag", `{"tag_name":""}`, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.code)
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			o := &Options{APIBase: srv.URL}
			if _, err := o.LatestRelease(); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestSwapBinary_ConcurrentLockRefused(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "devdiag")
	os.WriteFile(target, []byte("old"), 0o755)
	// Simulate an in-flight update holding the lock.
	if err := os.WriteFile(target+".update-lock", []byte("42\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	newBin := filepath.Join(t.TempDir(), "new")
	os.WriteFile(newBin, []byte("new"), 0o755)
	if err := SwapBinary(newBin, target); err == nil || !strings.Contains(err.Error(), "in progress") {
		t.Fatalf("error = %v, want lock refusal", err)
	}
	if data, _ := os.ReadFile(target); string(data) != "old" {
		t.Fatalf("target modified while locked: %q", data)
	}
}

func TestSwapBinary_StaleLockBroken(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "devdiag")
	os.WriteFile(target, []byte("old"), 0o755)
	lock := target + ".update-lock"
	os.WriteFile(lock, []byte("42\n"), 0o644)
	stale := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(lock, stale, stale); err != nil {
		t.Fatal(err)
	}
	newBin := filepath.Join(t.TempDir(), "new")
	os.WriteFile(newBin, []byte("new"), 0o755)
	if err := SwapBinary(newBin, target); err != nil {
		t.Fatalf("stale lock should be broken, got %v", err)
	}
	if data, _ := os.ReadFile(target); string(data) != "new" {
		t.Fatalf("target = %q, want new", data)
	}
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Fatalf("lock should be released after swap")
	}
}

func TestExtractBinary_TooManyEntries(t *testing.T) {
	entries := make([]tarEntry, 0, maxArchiveEntries+2)
	for i := 0; i < maxArchiveEntries+1; i++ {
		entries = append(entries, tarEntry{name: fmt.Sprintf("f%d", i), body: []byte("x")})
	}
	_, err := ExtractBinary(makeTarGz(t, entries), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "entries") {
		t.Fatalf("error = %v, want entry-cap refusal", err)
	}
}

func TestAuthHeaderAllowed_RejectsPlainHTTPGitHub(t *testing.T) {
	if authHeaderAllowed("http://api.github.com/repos/x") {
		t.Fatal("plain HTTP to github must not carry credentials")
	}
	if !authHeaderAllowed("http://127.0.0.1:1234/x") {
		t.Fatal("loopback test servers may carry credentials over HTTP")
	}
}

func TestIsLoopbackURL(t *testing.T) {
	cases := map[string]bool{
		"http://127.0.0.1:8080": true,
		"http://localhost:99":   true,
		"http://[::1]:9":        true,
		"https://github.com":    false,
		"https://evil.com":      false,
	}
	for u, want := range cases {
		if got := IsLoopbackURL(u); got != want {
			t.Errorf("IsLoopbackURL(%q) = %v, want %v", u, got, want)
		}
	}
}

func TestSwapBinary_PreservesTargetMode(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "devdiag")
	if err := os.WriteFile(target, []byte("old"), 0o700); err != nil {
		t.Fatal(err)
	}
	newBin := filepath.Join(t.TempDir(), "new")
	os.WriteFile(newBin, []byte("new"), 0o755)
	if err := SwapBinary(newBin, target); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode = %v, want 0700 preserved", fi.Mode().Perm())
	}
}

func TestOptions_OverridesIgnoredOutsideLoopback(t *testing.T) {
	o := &Options{
		APIBase:      "https://evil.example.com",
		DownloadBase: "https://mirror.example.com",
		GHPath:       "/tmp/fake-gh",
	}
	if got := o.apiBase(); got != "https://api.github.com" {
		t.Errorf("apiBase = %q, want canonical", got)
	}
	if got := o.downloadBase(); got != "https://github.com" {
		t.Errorf("downloadBase = %q, want canonical", got)
	}
	if got := o.ghPath(); got != "gh" {
		t.Errorf("ghPath = %q, want gh (override requires loopback API base)", got)
	}
}

func TestExtractBinary_PreservesPreexistingFileOnExclFailure(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "devdiag")
	if err := os.WriteFile(existing, []byte("preexisting"), 0o755); err != nil {
		t.Fatal(err)
	}
	body := []byte("new")
	archive := makeTarGz(t, []tarEntry{{name: "devdiag", body: body}})
	if _, err := ExtractBinary(archive, dir); err == nil {
		t.Fatal("expected O_EXCL failure against the pre-existing file")
	}
	data, err := os.ReadFile(existing)
	if err != nil || string(data) != "preexisting" {
		t.Fatalf("pre-existing file was destroyed: %q err=%v", data, err)
	}
}
