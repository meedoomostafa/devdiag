package updater

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// maxBinaryBytes caps the extracted binary size (decompression-bomb guard).
const maxBinaryBytes = 512 << 20

// ExtractBinary pulls the single `devdiag` regular file out of a release
// tar.gz into destDir and returns its path. Everything hostile is rejected:
// path traversal, absolute paths, symlinks, hardlinks, devices, duplicate
// binaries, and oversized entries. Non-binary files (LICENSE, README.md)
// are ignored.
func ExtractBinary(archive []byte, destDir string) (string, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return "", fmt.Errorf("release archive is not valid gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	outPath := ""
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("read release archive: %w", err)
		}
		name := hdr.Name
		clean := filepath.Clean(name)
		if filepath.IsAbs(clean) || clean == ".." || len(clean) >= 3 && clean[:3] == ".."+string(filepath.Separator) {
			return "", fmt.Errorf("release archive entry %q escapes the extraction directory; refusing", name)
		}
		if filepath.Base(clean) != "devdiag" {
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeReg:
		case tar.TypeSymlink, tar.TypeLink:
			return "", fmt.Errorf("release archive carries devdiag as a link (%q); refusing", name)
		default:
			return "", fmt.Errorf("release archive carries devdiag as a non-regular file (type %q); refusing", string(hdr.Typeflag))
		}
		if outPath != "" {
			return "", fmt.Errorf("release archive carries more than one devdiag binary; refusing")
		}
		if hdr.Size <= 0 || hdr.Size > maxBinaryBytes {
			return "", fmt.Errorf("release archive devdiag entry has implausible size %d; refusing", hdr.Size)
		}
		outPath = filepath.Join(destDir, "devdiag")
		f, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
		if err != nil {
			return "", fmt.Errorf("stage extracted binary: %w", err)
		}
		n, err := io.Copy(f, io.LimitReader(tr, hdr.Size+1))
		closeErr := f.Close()
		if err != nil {
			return "", fmt.Errorf("write extracted binary: %w", err)
		}
		if closeErr != nil {
			return "", fmt.Errorf("close extracted binary: %w", closeErr)
		}
		if n != hdr.Size {
			return "", fmt.Errorf("release archive devdiag entry is truncated; refusing")
		}
	}
	if outPath == "" {
		return "", fmt.Errorf("release archive does not contain a devdiag binary")
	}
	return outPath, nil
}
