package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/remote/target"
)

func TestRenderHuman(t *testing.T) {
	tr := &target.Target{Kind: target.KindSSH, Raw: "user@host", User: "user", Host: "host"}
	res := NewSyncResult(tr, "minimal", "20260516T203500Z_a19f3c", "~/.devdiag/remote/20260516T203500Z_a19f3c", []string{"env.sh", "aliases.sh"})
	res.RedactionStatus = "default"

	var buf bytes.Buffer
	if err := Render(res, "human", &buf); err != nil {
		t.Fatalf("Render human error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "sync completed") {
		t.Error("human output missing 'sync completed'")
	}
	if !strings.Contains(out, "user@host") {
		t.Error("human output missing target")
	}
	if !strings.Contains(out, "20260516T203500Z_a19f3c") {
		t.Error("human output missing session ID")
	}
}

func TestRenderJSON(t *testing.T) {
	tr := &target.Target{Kind: target.KindSSH, Raw: "user@host", User: "user", Host: "host"}
	res := NewSyncResult(tr, "minimal", "20260516T203500Z_a19f3c", "~/.devdiag/remote/20260516T203500Z_a19f3c", []string{"env.sh"})
	res.RedactionStatus = "default"

	var buf bytes.Buffer
	if err := Render(res, "json", &buf); err != nil {
		t.Fatalf("Render json error: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("JSON unmarshal error: %v", err)
	}
	if parsed["status"] != "synced" {
		t.Errorf("status = %v, want synced", parsed["status"])
	}
}

func TestRenderNDJSON(t *testing.T) {
	tr := &target.Target{Kind: target.KindSSH, Raw: "user@host", User: "user", Host: "host"}
	res := NewSyncResult(tr, "minimal", "20260516T203500Z_a19f3c", "~/.devdiag/remote/20260516T203500Z_a19f3c", []string{"env.sh"})
	res.RedactionStatus = "default"

	var buf bytes.Buffer
	if err := Render(res, "ndjson", &buf); err != nil {
		t.Fatalf("Render ndjson error: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 NDJSON line, got %d", len(lines))
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &parsed); err != nil {
		t.Fatalf("NDJSON line unmarshal error: %v", err)
	}
}
