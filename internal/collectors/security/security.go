package security

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

const (
	defaultMaxSecurityLogBytes = 512 * 1024
	maxSecurityDenialEvidence  = 20
)

var defaultSecurityLogPaths = []string{
	"/var/log/audit/audit.log",
	"/var/log/kern.log",
	"/var/log/syslog",
}

// Collector gathers non-mutating Linux security-module state.
type Collector struct {
	SELinuxEnforcePath  string
	AppArmorEnabledPath string
	SecurityLogPaths    []string
	MaxLogBytes         int64
	Root                string
}

func (c *Collector) Name() string {
	return "security"
}

func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	evidence := []schema.Evidence{
		{Source: "selinux_status", Value: c.selinuxStatus()},
		{Source: "apparmor_enabled", Value: c.apparmorEnabled()},
	}
	var notes []string
	logEvidence, logNotes := c.securityLogEvidence(ctx)
	evidence = append(evidence, logEvidence...)
	notes = append(notes, logNotes...)
	return schema.CollectorResult{
		Name:     c.Name(),
		Status:   schema.CollectorOK,
		Evidence: evidence,
		Notes:    notes,
	}, nil
}

func (c *Collector) selinuxStatus() string {
	path := c.SELinuxEnforcePath
	if path == "" {
		path = "/sys/fs/selinux/enforce"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "unavailable"
	}
	switch strings.TrimSpace(string(data)) {
	case "1":
		return "enforcing"
	case "0":
		return "permissive"
	default:
		return "unknown"
	}
}

func (c *Collector) securityLogEvidence(ctx context.Context) ([]schema.Evidence, []string) {
	paths := c.SecurityLogPaths
	if paths == nil {
		paths = defaultSecurityLogPaths
	}
	maxBytes := c.MaxLogBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxSecurityLogBytes
	}

	var evidence []schema.Evidence
	var notes []string
	for _, path := range paths {
		select {
		case <-ctx.Done():
			notes = append(notes, "security log scan canceled")
			return evidence, notes
		default:
		}
		data, err := readLogTail(path, maxBytes)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			if os.IsPermission(err) {
				evidence = append(evidence, schema.Evidence{Source: "security_log_access_denied", Value: path})
				continue
			}
			notes = append(notes, fmt.Sprintf("security log %s unavailable: %v", path, err))
			continue
		}
		lines := strings.Split(string(data), "\n")
		auditContexts := buildAuditRecordContexts(lines)
		for _, line := range lines {
			contextLine := line
			if id := auditRecordID(line); id != "" {
				contextLine = auditContexts[id]
			}
			if !lineMatchesRoot(contextLine, c.Root) {
				continue
			}
			source, value, ok := classifyDenialLineWithContext(line, contextLine)
			if !ok {
				continue
			}
			evidence = append(evidence, schema.Evidence{
				Source: source,
				Value:  fmt.Sprintf("log=%s %s", filepath.Base(path), value),
			})
			if len(evidence) >= maxSecurityDenialEvidence {
				notes = append(notes, fmt.Sprintf("security log denial evidence capped at %d entries", maxSecurityDenialEvidence))
				return evidence, notes
			}
		}
	}
	return evidence, notes
}

func buildAuditRecordContexts(lines []string) map[string]string {
	grouped := make(map[string][]string)
	for _, line := range lines {
		id := auditRecordID(line)
		if id == "" {
			continue
		}
		grouped[id] = append(grouped[id], line)
	}
	contexts := make(map[string]string, len(grouped))
	for id, group := range grouped {
		contexts[id] = strings.Join(group, " ")
	}
	return contexts
}

func auditRecordID(line string) string {
	start := strings.Index(line, "audit(")
	if start == -1 {
		return ""
	}
	rest := line[start+len("audit("):]
	end := strings.Index(rest, "):")
	if end == -1 {
		return ""
	}
	return rest[:end]
}

func lineMatchesRoot(line, root string) bool {
	if root == "" {
		return true
	}
	root = filepath.Clean(root)
	if root == "." || root == string(filepath.Separator) {
		return true
	}
	return strings.Contains(line, root)
}

func readLogTail(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("path is a directory")
	}
	if info.Size() > maxBytes {
		if _, err := f.Seek(info.Size()-maxBytes, io.SeekStart); err != nil {
			return nil, err
		}
	}
	return io.ReadAll(io.LimitReader(f, maxBytes))
}

func classifyDenialLine(line string) (string, string, bool) {
	return classifyDenialLineWithContext(line, line)
}

func classifyDenialLineWithContext(line, contextLine string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", false
	}
	lower := strings.ToLower(line)
	if strings.Contains(lower, "avc:") && strings.Contains(lower, "denied") {
		return "selinux_denial", summarizeSELinuxDenial(line, contextLine), true
	}
	if strings.Contains(lower, "apparmor") && strings.Contains(lower, "denied") {
		return "apparmor_denial", summarizeAppArmorDenial(line), true
	}
	return "", "", false
}

func summarizeSELinuxDenial(line, contextLine string) string {
	parts := []string{}
	if op := strings.TrimSpace(extractBetween(line, "{", "}")); op != "" {
		parts = append(parts, "operation="+op)
	}
	for _, key := range []string{"comm", "name", "cwd", "tclass", "scontext", "tcontext"} {
		source := line
		if key == "cwd" {
			source = contextLine
		}
		if value := extractValue(source, key); value != "" {
			outKey := key
			if key == "tclass" {
				outKey = "class"
			}
			parts = append(parts, outKey+"="+value)
		}
	}
	if selinuxContainerLabelHint(contextLine) {
		parts = append(parts, "container_label_hint=mount_relabel_z_or_Z")
	}
	return fallbackSummary(parts, line)
}

func selinuxContainerLabelHint(contextLine string) bool {
	scontext := extractValue(contextLine, "scontext")
	tcontext := extractValue(contextLine, "tcontext")
	if !strings.Contains(scontext, "container_t") {
		return false
	}
	for _, targetType := range []string{"default_t", "user_home_t", "unlabeled_t"} {
		if strings.Contains(tcontext, targetType) {
			return true
		}
	}
	return false
}

func summarizeAppArmorDenial(line string) string {
	parts := []string{}
	for _, key := range []string{"profile", "operation", "name", "comm"} {
		if value := extractValue(line, key); value != "" {
			parts = append(parts, key+"="+value)
		}
	}
	return fallbackSummary(parts, line)
}

func extractBetween(s, start, end string) string {
	startIdx := strings.Index(s, start)
	if startIdx == -1 {
		return ""
	}
	rest := s[startIdx+len(start):]
	endIdx := strings.Index(rest, end)
	if endIdx == -1 {
		return ""
	}
	return rest[:endIdx]
}

func extractValue(line, key string) string {
	prefix := key + "="
	idx := strings.Index(line, prefix)
	if idx == -1 {
		return ""
	}
	rest := line[idx+len(prefix):]
	if strings.HasPrefix(rest, "\"") {
		rest = rest[1:]
		end := strings.Index(rest, "\"")
		if end == -1 {
			return ""
		}
		return rest[:end]
	}
	end := strings.IndexAny(rest, " \t")
	if end == -1 {
		return rest
	}
	return rest[:end]
}

func fallbackSummary(parts []string, line string) string {
	if len(parts) > 0 {
		return strings.Join(parts, " ")
	}
	const maxSummaryLen = 240
	line = strings.Join(strings.Fields(line), " ")
	if len(line) <= maxSummaryLen {
		return line
	}
	return strings.TrimSpace(line[:maxSummaryLen-3]) + "..."
}

func (c *Collector) apparmorEnabled() string {
	path := c.AppArmorEnabledPath
	if path == "" {
		path = "/sys/module/apparmor/parameters/enabled"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "unavailable"
	}
	switch strings.ToUpper(strings.TrimSpace(string(data))) {
	case "Y", "YES", "1":
		return "true"
	case "N", "NO", "0":
		return "false"
	default:
		return "unknown"
	}
}
