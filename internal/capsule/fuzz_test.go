package capsule

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"
)

// FuzzInspectFromBytes drives the capsule inspector with arbitrary bytes.
// Capsules are support bundles that users receive from other people, so the
// inspector parses untrusted input: it must never panic and must never
// consume unbounded memory, regardless of how hostile the archive is.
func FuzzInspectFromBytes(f *testing.F) {
	// Seed: a well-formed minimal capsule.
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	manifest := []byte(`{"schema_version":"1","devdiag_version":"v0.0.0"}`)
	_ = tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0o644, Size: int64(len(manifest)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(manifest)
	_ = tw.Close()
	_ = gz.Close()
	f.Add(buf.Bytes())

	// Seed: empty input, non-gzip input, and gzip-of-nothing.
	f.Add([]byte{})
	f.Add([]byte("not a gzip stream at all"))
	var emptyGz bytes.Buffer
	ez := gzip.NewWriter(&emptyGz)
	_ = ez.Close()
	f.Add(emptyGz.Bytes())

	// Seed: path traversal in an entry name.
	var evil bytes.Buffer
	egz := gzip.NewWriter(&evil)
	etw := tar.NewWriter(egz)
	_ = etw.WriteHeader(&tar.Header{Name: "../../etc/passwd", Mode: 0o644, Size: 1, Typeflag: tar.TypeReg})
	_, _ = etw.Write([]byte("x"))
	_ = etw.Close()
	_ = egz.Close()
	f.Add(evil.Bytes())

	f.Fuzz(func(t *testing.T, data []byte) {
		// Contract: never panic. Errors are fine; crashes are not.
		res, err := InspectFromBytes(data)
		if err != nil {
			return
		}
		if res == nil {
			t.Fatal("InspectFromBytes returned nil result and nil error")
		}
		// Contract: bounded output. A hostile archive must not be able to
		// make the inspector accumulate unbounded entries.
		if len(res.FileList) > maxCapsuleEntries {
			t.Fatalf("FileList grew to %d entries, cap is %d", len(res.FileList), maxCapsuleEntries)
		}
	})
}
