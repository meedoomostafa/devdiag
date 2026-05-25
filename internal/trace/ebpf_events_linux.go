//go:build linux && (amd64 || arm64)

package trace

import (
	"fmt"
	"net"
	"time"
)

const (
	ebpfEventOpenat  uint32 = 1
	ebpfEventExecve  uint32 = 2
	ebpfEventConnect uint32 = 3
	ebpfEventBind    uint32 = 4
	ebpfEventFork    uint32 = 5
)

func eventsFromEBPFKernelEvents(raw []devdiagEbpfTraceEvent, scopes []Scope) []Event {
	scopeSet := make(map[Scope]bool, len(scopes))
	for _, scope := range scopes {
		scopeSet[scope] = true
	}
	events := make([]Event, 0, len(raw))
	for _, rawEvent := range raw {
		scope, syscallName, ok := ebpfEventMetadata(rawEvent.EventType)
		if !ok {
			continue
		}
		if len(scopeSet) > 0 && !scopeSet[scope] {
			continue
		}
		result, errno := ebpfResultAndError(rawEvent.Ret)
		event := Event{
			Timestamp: time.Unix(0, int64(rawEvent.TimestampNs)),
			PID:       int(rawEvent.Pid),
			Syscall:   syscallName,
			Result:    result,
			Error:     errno,
		}
		switch rawEvent.EventType {
		case ebpfEventOpenat, ebpfEventExecve:
			if arg := ebpfCString(rawEvent.Arg0[:]); arg != "" {
				event.Args = []string{fmt.Sprintf("%q", arg)}
			}
		case ebpfEventConnect, ebpfEventBind:
			if arg := ebpfSockaddrArg(rawEvent); arg != "" {
				event.Args = []string{arg}
			}
		case ebpfEventFork:
			event.Args = []string{fmt.Sprintf("child_pid=%d", rawEvent.Pid), fmt.Sprintf("parent_pid=%d", rawEvent.Ppid)}
		}
		events = append(events, event)
	}
	return events
}

func ebpfEventMetadata(eventType uint32) (Scope, string, bool) {
	switch eventType {
	case ebpfEventOpenat:
		return ScopeFile, "openat", true
	case ebpfEventExecve:
		return ScopeProcess, "execve", true
	case ebpfEventConnect:
		return ScopeNetwork, "connect", true
	case ebpfEventBind:
		return ScopeNetwork, "bind", true
	case ebpfEventFork:
		return ScopeProcess, "clone", true
	default:
		return "", "", false
	}
}

func ebpfResultAndError(ret int64) (string, string) {
	if ret >= 0 {
		return fmt.Sprintf("%d", ret), ""
	}
	if name := ebpfErrnoName(-ret); name != "" {
		return "-1", name
	}
	return fmt.Sprintf("%d", ret), fmt.Sprintf("ERRNO_%d", -ret)
}

func ebpfErrnoName(errno int64) string {
	switch errno {
	case 1:
		return "EPERM"
	case 2:
		return "ENOENT"
	case 13:
		return "EACCES"
	case 98:
		return "EADDRINUSE"
	case 101:
		return "ENETUNREACH"
	case 110:
		return "ETIMEDOUT"
	case 111:
		return "ECONNREFUSED"
	case 113:
		return "EHOSTUNREACH"
	default:
		return ""
	}
}

func ebpfCString(raw []uint8) string {
	for i, b := range raw {
		if b == 0 {
			return string(raw[:i])
		}
	}
	return string(raw)
}

func ebpfSockaddrArg(raw devdiagEbpfTraceEvent) string {
	if raw.Family != 2 || raw.Port == 0 {
		return ""
	}
	ip := net.IPv4(byte(raw.Addr4), byte(raw.Addr4>>8), byte(raw.Addr4>>16), byte(raw.Addr4>>24)).String()
	return fmt.Sprintf(`{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr("%s")}`, raw.Port, ip)
}
