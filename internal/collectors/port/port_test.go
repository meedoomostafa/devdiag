package port

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

func TestCollector_Name(t *testing.T) {
	c := &Collector{}
	if got := c.Name(); got != "port" {
		t.Errorf("Name() = %q, want %q", got, "port")
	}
}

func TestCollector_Collect(t *testing.T) {
	c := &Collector{}
	ctx := context.Background()
	res, err := c.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect error: %v", err)
	}
	if res.Status != schema.CollectorOK {
		t.Errorf("status = %q, want ok", res.Status)
	}
	// On Linux, should have some evidence; on non-Linux, may be empty but ok
}

func TestParseProcNetTCP(t *testing.T) {
	// Create mock /proc/net/tcp
	tmpDir := t.TempDir()
	mockPath := filepath.Join(tmpDir, "tcp")
	data := `  sl  local_address rem_address   st tx_queue:rx_queue tr:tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345
   1: 0100007F:1538 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346
`
	if err := os.WriteFile(mockPath, []byte(data), 0644); err != nil {
		t.Fatal(err)
	}

	addrs, err := parseProcNetTCP(mockPath)
	if err != nil {
		t.Fatalf("parseProcNetTCP error: %v", err)
	}
	if len(addrs) != 2 {
		t.Fatalf("expected 2 LISTEN sockets, got %d", len(addrs))
	}

	// 0.0.0.0:8080 (0x1F90 = 8080)
	if addrs[0].port != 8080 {
		t.Errorf("port[0] = %d, want 8080", addrs[0].port)
	}
	// 127.0.0.1:5432 (0x1538 = 5432)
	if addrs[1].port != 5432 {
		t.Errorf("port[1] = %d, want 5432", addrs[1].port)
	}
}

func TestParseLocalAddr(t *testing.T) {
	addr, port, err := parseLocalAddr("0100007F:1F90")
	if err != nil {
		t.Fatalf("parseLocalAddr error: %v", err)
	}
	if port != 8080 {
		t.Errorf("port = %d, want 8080", port)
	}
	if addr != "127.0.0.1" {
		t.Errorf("addr = %q, want 127.0.0.1", addr)
	}
}

func TestParseHexAddr(t *testing.T) {
	if got := parseHexAddr("0100007F"); got != "127.0.0.1" {
		t.Errorf("parseHexAddr(0100007F) = %q, want 127.0.0.1", got)
	}
	if got := parseHexAddr("00000000"); got != "0.0.0.0" {
		t.Errorf("parseHexAddr(00000000) = %q, want 0.0.0.0", got)
	}
}
