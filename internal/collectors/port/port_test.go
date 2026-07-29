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

// TestParseLocalAddr_RejectsOutOfRangePort pins that a hostile or corrupt
// /proc/net/tcp line cannot produce a wrapped/nonsense port. CodeQL flagged
// the unbounded ParseInt -> int conversion (go/incorrect-integer-conversion).
func TestParseLocalAddr_RejectsOutOfRangePort(t *testing.T) {
	cases := []string{
		"0100007F:1FFFF",            // 131071, above uint16
		"0100007F:FFFFFFFFFFFFFFFF", // overflows int64 parse
		"0100007F:10000",            // 65536, one past the max port
	}
	for _, in := range cases {
		if _, port, err := parseLocalAddr(in); err == nil {
			t.Errorf("parseLocalAddr(%q) accepted out-of-range port %d, want error", in, port)
		}
	}
}

// TestParseHexAddr_RejectsMalformedOctets pins that non-hex or out-of-range
// octets do not silently truncate into a plausible-looking address.
func TestParseHexAddr_RejectsMalformedOctets(t *testing.T) {
	// "GG" is not hex; the old code swallowed the error and used byte(0).
	if got := parseHexAddr("0100GG7F"); got != "" {
		t.Errorf("parseHexAddr with non-hex octet = %q, want empty string", got)
	}
}

// TestParseProcNetTCP_SkipsMalformedLines pins that unparsable lines are
// dropped rather than surfacing as evidence with an empty address.
func TestParseProcNetTCP_SkipsMalformedLines(t *testing.T) {
	data := "  sl  local_address rem_address   st\n" +
		"   0: 0100GG7F:1F90 00000000:0000 0A\n" + // bad hex address
		"   1: 0100007F:1FFFF 00000000:0000 0A\n" + // out-of-range port
		"   2: 0100007F:1F90 00000000:0000 0A\n" // valid
	tmpDir := t.TempDir()
	mockPath := filepath.Join(tmpDir, "tcp")
	if err := os.WriteFile(mockPath, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := parseProcNetTCP(mockPath)
	if err != nil {
		t.Fatalf("parseProcNetTCP error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d listeners %+v, want only the valid line", len(got), got)
	}
	if got[0].addr != "127.0.0.1" || got[0].port != 8080 {
		t.Errorf("got %+v, want 127.0.0.1:8080", got[0])
	}
}

// TestParseLocalAddr_AcceptsMaxPort pins that the 16-bit bound accepts the
// legitimate maximum port; the bound must reject overflow, not valid input.
func TestParseLocalAddr_AcceptsMaxPort(t *testing.T) {
	addr, port, err := parseLocalAddr("0100007F:FFFF")
	if err != nil {
		t.Fatalf("parseLocalAddr(max port) error: %v", err)
	}
	if port != 65535 {
		t.Errorf("port = %d, want 65535", port)
	}
	if addr != "127.0.0.1" {
		t.Errorf("addr = %q, want 127.0.0.1", addr)
	}
}

// TestParseHexAddr_IPv6Unaffected pins that the 32-char IPv6 form still
// returns the documented placeholder rather than being caught by the new
// IPv4 octet validation.
func TestParseHexAddr_IPv6Unaffected(t *testing.T) {
	ipv6 := "00000000000000000000000001000000"
	if got := parseHexAddr(ipv6); got != "::" {
		t.Errorf("parseHexAddr(ipv6) = %q, want ::", got)
	}
}
