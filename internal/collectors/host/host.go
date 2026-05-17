package host

import (
	"context"
	"os"
	"runtime"
	"strings"
	"syscall"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Collector collects minimal host metadata.
type Collector struct{}

func (c *Collector) Name() string {
	return "host"
}

func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	evidence := []schema.Evidence{}

	// OS from /etc/os-release
	id, version := parseOSRelease("/etc/os-release")
	if id != "" {
		evidence = append(evidence, schema.Evidence{Source: "host_os_id", Value: id})
	}
	if version != "" {
		evidence = append(evidence, schema.Evidence{Source: "host_os_version", Value: version})
	}

	// Kernel and architecture via syscall.Uname
	var uname syscall.Utsname
	if err := syscall.Uname(&uname); err == nil {
		kernel := utsString(uname.Release)
		arch := utsString(uname.Machine)
		if kernel != "" {
			evidence = append(evidence, schema.Evidence{Source: "host_kernel", Value: kernel})
		}
		if arch != "" {
			evidence = append(evidence, schema.Evidence{Source: "host_arch", Value: arch})
		}
	} else {
		// Fallback to runtime.GOARCH
		evidence = append(evidence, schema.Evidence{Source: "host_arch", Value: runtime.GOARCH})
	}

	// Go runtime OS as a fallback hint
	evidence = append(evidence, schema.Evidence{Source: "host_goos", Value: runtime.GOOS})
	if shell := shellName(os.Getenv("SHELL")); shell != "" {
		evidence = append(evidence, schema.Evidence{Source: "host_shell", Value: shell})
	}

	return schema.CollectorResult{
		Name:     c.Name(),
		Status:   schema.CollectorOK,
		Evidence: evidence,
	}, nil
}

func parseOSRelease(path string) (id, version string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		}
		if strings.HasPrefix(line, "VERSION_ID=") {
			version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), `"`)
		}
	}
	return
}

func utsString(a [65]int8) string {
	var buf [65]byte
	for i, v := range a {
		if v == 0 {
			return string(buf[:i])
		}
		buf[i] = byte(v)
	}
	return string(buf[:])
}

func shellName(shell string) string {
	shell = strings.TrimSpace(shell)
	if shell == "" {
		return ""
	}
	if idx := strings.LastIndex(shell, "/"); idx != -1 {
		return shell[idx+1:]
	}
	return shell
}
