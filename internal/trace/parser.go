package trace

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var pidRegex = regexp.MustCompile(`^\[pid\s+(\d+)\]\s*`)
var timeRegex = regexp.MustCompile(`^(\d{2}):(\d{2}):(\d{2})\.(\d{6})\s*`)

// ParseLine parses a single strace line into an Event.
// Returns an error for non-event lines; callers may ignore these.
func ParseLine(line string) (*Event, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, fmt.Errorf("empty line")
	}

	// Skip metadata lines
	if strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "---") {
		return nil, fmt.Errorf("metadata line")
	}
	if strings.Contains(line, "<unfinished ...>") || strings.Contains(line, "<... ") {
		return nil, fmt.Errorf("unfinished/resumed line")
	}

	// Extract PID first (optional prefix like "[pid  1234]")
	pid := 0
	if m := pidRegex.FindStringSubmatch(line); m != nil {
		pid, _ = strconv.Atoi(m[1])
		line = line[len(m[0]):]
		line = strings.TrimSpace(line)
	}

	// Strip optional leading numeric PID if strace emits bare PID format
	fields := strings.Fields(line)
	if len(fields) >= 2 {
		if _, err := strconv.Atoi(fields[0]); err == nil {
			// Bare numeric PID before timestamp
			line = strings.TrimSpace(line[len(fields[0]):])
		}
	}

	// Extract timestamp
	var ts time.Time
	if m := timeRegex.FindStringSubmatch(line); m != nil {
		h, _ := strconv.Atoi(m[1])
		min, _ := strconv.Atoi(m[2])
		s, _ := strconv.Atoi(m[3])
		us, _ := strconv.Atoi(m[4])
		ts = time.Date(0, 1, 1, h, min, s, us*1000, time.UTC)
		line = line[len(m[0]):]
		line = strings.TrimSpace(line)
	}

	// Extract syscall name and args
	openParen := strings.Index(line, "(")
	if openParen == -1 {
		return nil, fmt.Errorf("no syscall found")
	}
	syscall := line[:openParen]
	rest := line[openParen:]

	// Find the matching ") =" after the syscall args by tracking parenthesis depth
	result := ""
	errStr := ""
	depth := 0
	closeParen := -1
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		switch c {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				closeParen = i
			}
		}
		if closeParen != -1 {
			break
		}
	}
	if closeParen != -1 {
		after := strings.TrimSpace(rest[closeParen+1:])
		if strings.HasPrefix(after, "=") {
			resultPart := strings.TrimSpace(after[1:])
			rest = rest[:closeParen+1]
			if strings.HasPrefix(resultPart, "-1") {
				parts := strings.Fields(resultPart)
				if len(parts) >= 2 {
					result = parts[0]
					errStr = parts[1]
				}
			} else {
				// Extract only the first token, stopping at space or <
				if idx := strings.IndexAny(resultPart, " <"); idx != -1 {
					result = resultPart[:idx]
				} else {
					result = resultPart
				}
			}
		}
	}

	args := parseArgs(rest)

	return &Event{
		Timestamp: ts,
		PID:       pid,
		Syscall:   syscall,
		Args:      args,
		Result:    result,
		Error:     errStr,
	}, nil
}

func parseArgs(s string) []string {
	s = strings.TrimPrefix(s, "(")
	s = strings.TrimSuffix(s, ")")
	if s == "" {
		return nil
	}
	var args []string
	depth := 0
	inQuote := false
	escaped := false
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' && inQuote {
			escaped = true
			continue
		}
		switch c {
		case '"':
			inQuote = !inQuote
		case '{', '[', '(':
			if !inQuote {
				depth++
			}
		case '}', ']', ')':
			if !inQuote {
				depth--
			}
		case ',':
			if !inQuote && depth == 0 {
				arg := strings.TrimSpace(s[start:i])
				args = append(args, arg)
				start = i + 1
			}
		}
	}
	if start < len(s) {
		args = append(args, strings.TrimSpace(s[start:]))
	}
	return args
}
