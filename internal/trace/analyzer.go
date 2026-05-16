package trace

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

const maxEvidencePerFinding = 20

// noisyPaths are known paths that programs probe intentionally and should not produce findings.
var noisyPaths = []string{
	"/usr/share/locale",
	"/etc/ld.so.preload",
	"/usr/lib/locale",
	"/usr/lib/x86_64-linux-gnu",
}

// isNoisyPath returns true if the path is a known benign probe path.
func isNoisyPath(path string) bool {
	for _, prefix := range noisyPaths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// capEvidence limits evidence count and adds a summary note when capped.
func capEvidence(evs []schema.Evidence) []schema.Evidence {
	if len(evs) <= maxEvidencePerFinding {
		return evs
	}
	capped := evs[:maxEvidencePerFinding]
	omitted := len(evs) - maxEvidencePerFinding
	capped = append(capped, schema.Evidence{
		Source: "trace_evidence_omitted",
		Value:  fmt.Sprintf("%d additional entries omitted", omitted),
	})
	return capped
}

// sortedMapKeys returns sorted keys for stable map iteration.
func sortedMapKeys(m map[string][]schema.Evidence) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Analyze correlates trace events into findings, aggregating evidence by category.
func Analyze(events []Event) []schema.Finding {
	fileNotFound := make(map[string][]schema.Evidence)
	permDenied := make(map[string][]schema.Evidence)
	connRefused := make(map[string][]schema.Evidence)

	seenFile := make(map[string]bool)
	seenPerm := make(map[string]bool)
	seenConn := make(map[string]bool)

	for _, ev := range events {
		if ev.Result != "-1" || ev.Error == "" {
			continue
		}
		switch ev.Error {
		case "ENOENT":
			path := extractPath(ev.Args)
			if path != "" && !isNoisyPath(path) && !seenFile[path] {
				seenFile[path] = true
				fileNotFound[path] = append(fileNotFound[path], schema.Evidence{
					Source: "trace_open_path", Value: path,
				})
			}
		case "EACCES", "EPERM":
			path := extractPath(ev.Args)
			key := path + "|" + ev.Error
			if path != "" && !seenPerm[key] {
				seenPerm[key] = true
				permDenied[path] = append(permDenied[path], schema.Evidence{
					Source: "trace_open_path", Value: path,
				})
				permDenied[path] = append(permDenied[path], schema.Evidence{
					Source: "trace_errno", Value: ev.Error,
				})
			}
		case "ECONNREFUSED":
			host, port, raw := extractHostPort(ev.Args)
			key := host + ":" + port
			if host == "" && port == "" {
				key = raw
			}
			connKey := key + "|ECONNREFUSED"
			if key != "" && !seenConn[connKey] {
				seenConn[connKey] = true
				if host == "" && port == "" {
					connRefused[key] = append(connRefused[key], schema.Evidence{
						Source: "trace_connect_addr", Value: raw,
					})
				} else {
					connRefused[key] = append(connRefused[key], schema.Evidence{
						Source: "trace_connect_host", Value: host,
					})
					connRefused[key] = append(connRefused[key], schema.Evidence{
						Source: "trace_connect_port", Value: port,
					})
				}
				connRefused[key] = append(connRefused[key], schema.Evidence{
					Source: "trace_errno", Value: "ECONNREFUSED",
				})
			}
		}
	}

	var findings []schema.Finding

	// Build F-TRACE-FILE-001 (aggregate all missing paths into one finding)
	if len(fileNotFound) > 0 {
		var evidence []schema.Evidence
		for _, k := range sortedMapKeys(fileNotFound) {
			evidence = append(evidence, fileNotFound[k]...)
		}
		findings = append(findings, schema.Finding{
			ID:           "F-TRACE-FILE-001",
			Title:        "File not found during trace",
			Severity:     schema.SeverityLow,
			Confidence:   0.5,
			Symptom:      "Process attempted to open files that do not exist",
			LikelyCauses: []string{"Wrong working directory", "Missing config file", "Hardcoded path"},
			FixHints:     []string{"check-wd", "verify-config-path"},
			Evidence:     capEvidence(evidence),
		})
	}

	// Build F-TRACE-FILE-002 (permission denied) — aggregate all paths into one finding
	if len(permDenied) > 0 {
		var evidence []schema.Evidence
		for _, k := range sortedMapKeys(permDenied) {
			evidence = append(evidence, permDenied[k]...)
		}
		findings = append(findings, schema.Finding{
			ID:           "F-TRACE-FILE-002",
			Title:        "Permission denied during trace",
			Severity:     schema.SeverityMedium,
			Confidence:   0.7,
			Symptom:      "Process was denied access to a file or directory",
			LikelyCauses: []string{"Insufficient permissions on parent directory", "Wrong user"},
			FixHints:     []string{"check-parent-permissions", "check-file-owner"},
			Evidence:     capEvidence(evidence),
		})
	}

	// Build F-TRACE-NET-001 (connection refused) — aggregate all addresses into one finding
	if len(connRefused) > 0 {
		var evidence []schema.Evidence
		var hasUnix bool
		for _, key := range sortedMapKeys(connRefused) {
			evidence = append(evidence, connRefused[key]...)
			if strings.HasSuffix(key, ":unix") || key == "unix" {
				hasUnix = true
			}
		}
		fixHints := []string{"start-service", "verify-port", "verify-service-listening"}
		if hasUnix {
			fixHints = []string{"verify-unix-socket"}
		}
		findings = append(findings, schema.Finding{
			ID:           "F-TRACE-NET-001",
			Title:        "Connection refused during trace",
			Severity:     schema.SeverityHigh,
			Confidence:   0.8,
			Symptom:      "Process attempted to connect to a service that refused the connection",
			LikelyCauses: []string{"Service not running", "Wrong port/host", "Firewall"},
			FixHints:     fixHints,
			Evidence:     capEvidence(evidence),
		})
	}

	return findings
}

func extractPath(args []string) string {
	for _, a := range args {
		if strings.HasPrefix(a, `"`) && strings.HasSuffix(a, `"`) {
			return strings.Trim(a, `"`)
		}
	}
	return ""
}

var inetAddrRegex = regexp.MustCompile(`inet_addr\("([^"]+)"\)`)
var htonsRegex = regexp.MustCompile(`sin_port=htons\((\d+)\)`)
var unixPathRegex = regexp.MustCompile(`sun_path="([^"]+)"`)

// extractHostPort parses host, port, and raw sockaddr from connect args.
// Returns raw arg string when no structured address is found.
func extractHostPort(args []string) (host, port, raw string) {
	for _, a := range args {
		if strings.Contains(a, "sa_family=") || strings.Contains(a, "sin_port") || strings.Contains(a, "sun_path") {
			raw = a
		}
		if m := inetAddrRegex.FindStringSubmatch(a); m != nil {
			host = m[1]
		}
		if m := htonsRegex.FindStringSubmatch(a); m != nil {
			port = m[1]
		}
		if m := unixPathRegex.FindStringSubmatch(a); m != nil {
			host = m[1]
			port = "unix"
		}
	}
	return
}
