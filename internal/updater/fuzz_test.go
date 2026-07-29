package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"strings"
	"testing"
)

// FuzzExtractBinary drives the release-archive extractor with arbitrary
// bytes. This parses attacker-influenceable input in the update path, so it
// must never panic, never escape the destination directory, and never
// produce a binary from a malformed archive.
func FuzzExtractBinary(f *testing.F) {
	mk := func(entries func(*tar.Writer)) []byte {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		tw := tar.NewWriter(gz)
		entries(tw)
		_ = tw.Close()
		_ = gz.Close()
		return buf.Bytes()
	}

	// Valid archive.
	f.Add(mk(func(tw *tar.Writer) {
		body := []byte("#!/bin/sh\necho hi\n")
		_ = tw.WriteHeader(&tar.Header{Name: "devdiag", Mode: 0o755, Size: int64(len(body)), Typeflag: tar.TypeReg})
		_, _ = tw.Write(body)
	}))
	// Traversal, symlink, duplicate, and empty variants.
	f.Add(mk(func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "../devdiag", Mode: 0o755, Size: 1, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("x"))
	}))
	f.Add(mk(func(tw *tar.Writer) {
		_ = tw.WriteHeader(&tar.Header{Name: "devdiag", Typeflag: tar.TypeSymlink, Linkname: "/bin/sh"})
	}))
	f.Add([]byte{})
	f.Add([]byte("plain text, not gzip"))

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path, err := ExtractBinary(data, dir)
		if err != nil {
			if path != "" {
				t.Fatalf("error returned alongside a path %q", path)
			}
			return
		}
		// Contract: the extracted file is always the fixed destination
		// inside dir - no archive entry may redirect it elsewhere.
		want := dir + string(os.PathSeparator) + "devdiag"
		if path != want {
			t.Fatalf("extracted to %q, want %q", path, want)
		}
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("reported success but file missing: %v", statErr)
		}
	})
}

// FuzzChecksumFor drives the checksums.txt parser. A malformed or hostile
// checksums file must never panic and must never return a digest that is
// not a well-formed 64-char hex string.
func FuzzChecksumFor(f *testing.F) {
	f.Add(strings.Repeat("ab", 32)+"  asset.tar.gz\n", "asset.tar.gz")
	f.Add("", "asset.tar.gz")
	f.Add("garbage\n\n\x00\n", "asset.tar.gz")
	f.Add(strings.Repeat("ab", 32)+"  *asset.tar.gz\n", "asset.tar.gz")

	f.Fuzz(func(t *testing.T, checksums, name string) {
		got, err := checksumFor([]byte(checksums), name)
		if err != nil {
			if got != "" {
				t.Fatalf("error returned alongside digest %q", got)
			}
			return
		}
		if len(got) != 64 || !isHex(got) {
			t.Fatalf("accepted malformed digest %q for %q", got, name)
		}
	})
}
