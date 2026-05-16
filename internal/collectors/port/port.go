package port

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Collector scans listening ports from /proc/net/tcp and /proc/net/tcp6.
type Collector struct{}

func (c *Collector) Name() string {
	return "port"
}

func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	evidence := []schema.Evidence{}

	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		ports, err := parseProcNetTCP(path)
		if err != nil {
			// Permission denied or file missing is partial, not fatal
			continue
		}
		for _, p := range ports {
			evidence = append(evidence, schema.Evidence{
				Source: fmt.Sprintf("host_listen_port_%s", p.addr),
				Value:  strconv.Itoa(p.port),
			})
		}
	}

	return schema.CollectorResult{
		Name:     c.Name(),
		Status:   schema.CollectorOK,
		Evidence: evidence,
	}, nil
}

type listenAddr struct {
	addr string
	port int
}

func parseProcNetTCP(path string) ([]listenAddr, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var results []listenAddr
	scanner := bufio.NewScanner(f)
	// Skip header line
	if scanner.Scan() {
		// header
	}
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// local_address is field 1, st is field 3
		localAddr := fields[1]
		state := fields[3]
		// TCP_LISTEN = 0A
		if state != "0A" {
			continue
		}
		addr, port, err := parseLocalAddr(localAddr)
		if err != nil {
			continue
		}
		results = append(results, listenAddr{addr: addr, port: port})
	}
	return results, scanner.Err()
}

func parseLocalAddr(s string) (string, int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid address")
	}
	// Port is little-endian hex
	portHex := parts[1]
	port, err := strconv.ParseInt(portHex, 16, 64)
	if err != nil {
		return "", 0, err
	}

	// Address is hex; for IPv4 it's little-endian 32-bit
	addrHex := parts[0]
	addr := parseHexAddr(addrHex)
	return addr, int(port), nil
}

func parseHexAddr(hex string) string {
	if len(hex) == 8 {
		// IPv4 little-endian: 0100007F = 127.0.0.1
		b := make([]byte, 4)
		for i := 0; i < 4; i++ {
			n, _ := strconv.ParseInt(hex[i*2:i*2+2], 16, 64)
			b[3-i] = byte(n) // reverse for little-endian
		}
		return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
	}
	// IPv6: return raw for now
	return "::"
}
