package trace

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseOpenat(t *testing.T) {
	line := `06:01:23.456789 openat(AT_FDCWD, "/etc/passwd", O_RDONLY|O_CLOEXEC) = 3</etc/passwd>`
	ev, err := ParseLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.Syscall != "openat" {
		t.Fatalf("expected openat, got %s", ev.Syscall)
	}
	if len(ev.Args) != 3 {
		t.Fatalf("expected 3 args, got %d", len(ev.Args))
	}
	if ev.Result != "3" {
		t.Fatalf("expected result 3, got %s", ev.Result)
	}
}

func TestParseOpenatENOENT(t *testing.T) {
	line := `06:01:23.456789 openat(AT_FDCWD, "/missing/file", O_RDONLY) = -1 ENOENT (No such file or directory)`
	ev, err := ParseLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.Syscall != "openat" {
		t.Fatalf("expected openat, got %s", ev.Syscall)
	}
	if ev.Result != "-1" {
		t.Fatalf("expected result -1, got %s", ev.Result)
	}
	if ev.Error != "ENOENT" {
		t.Fatalf("expected ENOENT, got %q", ev.Error)
	}
}

func TestParseConnect(t *testing.T) {
	line := `06:01:23.456789 connect(3, {sa_family=AF_INET, sin_port=htons(5432), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 ECONNREFUSED (Connection refused)`
	ev, err := ParseLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.Syscall != "connect" {
		t.Fatalf("expected connect, got %s", ev.Syscall)
	}
	if ev.Result != "-1" {
		t.Fatalf("expected result -1, got %s", ev.Result)
	}
	if ev.Error != "ECONNREFUSED" {
		t.Fatalf("expected ECONNREFUSED, got %q", ev.Error)
	}
}

func TestParsePIDPrefix(t *testing.T) {
	line := `[pid  1234] 06:01:23.456789 openat(AT_FDCWD, "/tmp/test", O_RDONLY) = 3`
	ev, err := ParseLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.PID != 1234 {
		t.Fatalf("expected pid 1234, got %d", ev.PID)
	}
}

func TestParseBarePIDPrefix(t *testing.T) {
	line := `1234 06:01:23.456789 openat(AT_FDCWD, "/tmp/test", O_RDONLY) = 3`
	ev, err := ParseLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.PID != 1234 {
		t.Fatalf("expected pid 1234, got %d", ev.PID)
	}
}

func TestParseDuration(t *testing.T) {
	line := `06:01:23.456789 openat(AT_FDCWD, "/tmp/test", O_RDONLY) = 3 <0.000123>`
	ev, err := ParseLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.Duration != 123*time.Microsecond {
		t.Fatalf("expected duration 123µs, got %s", ev.Duration)
	}
}

func TestParseExitLine(t *testing.T) {
	line := `+++ exited with 0 +++`
	_, err := ParseLine(line)
	if err == nil {
		t.Fatal("expected exit line to be skipped")
	}
}

func TestParseSignalLine(t *testing.T) {
	line := `--- SIGCHLD {si_signo=SIGCHLD, si_code=CLD_EXITED, si_pid=1234, si_uid=1000, si_status=0, si_utime=0, si_stime=0} ---`
	_, err := ParseLine(line)
	if err == nil {
		t.Fatal("expected signal line to be skipped")
	}
}

func TestParseUnfinished(t *testing.T) {
	line := `06:01:23.456789 openat(AT_FDCWD, "/tmp/test", O_RDONLY <unfinished ...>`
	_, err := ParseLine(line)
	if err == nil {
		t.Fatal("expected unfinished line to be skipped")
	}
}

func TestParseResumed(t *testing.T) {
	line := `06:01:23.456789 <... openat resumed>) = 3`
	_, err := ParseLine(line)
	if err == nil {
		t.Fatal("expected resumed line to be skipped")
	}
}

func TestParseExecveWithEqualsInArg(t *testing.T) {
	line := `06:01:23.456789 execve("/usr/bin/env", ["env", "A=B"], 0x7fff) = 0`
	ev, err := ParseLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.Syscall != "execve" {
		t.Fatalf("expected execve, got %s", ev.Syscall)
	}
	if ev.Result != "0" {
		t.Fatalf("expected result 0, got %s", ev.Result)
	}
	// parseArgs treats nested arrays as one arg due to bracket depth tracking.
	found := false
	for _, a := range ev.Args {
		if strings.Contains(a, `"A=B"`) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected arg containing 'A=B' preserved, got %v", ev.Args)
	}
}

func TestParseEscapedQuote(t *testing.T) {
	line := `06:01:23.456789 openat(AT_FDCWD, "file\"name", O_RDONLY) = 3`
	ev, err := ParseLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ev.Args) < 2 || ev.Args[1] != `"file\"name"` {
		t.Fatalf("expected escaped quote preserved, got %v", ev.Args)
	}
}

func TestParseQuotedParenInPath(t *testing.T) {
	line := `06:01:23.456789 openat(AT_FDCWD, "/tmp/a)b", O_RDONLY) = -1 ENOENT (No such file or directory)`
	ev, err := ParseLine(line)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.Result != "-1" {
		t.Fatalf("expected result -1, got %s", ev.Result)
	}
	if ev.Error != "ENOENT" {
		t.Fatalf("expected ENOENT, got %q", ev.Error)
	}
	if len(ev.Args) < 2 || ev.Args[1] != `"/tmp/a)b"` {
		t.Fatalf("expected quoted path with paren preserved, got %v", ev.Args)
	}
}

func TestReadTraceFileMergesUnfinishedResumed(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "trace-*.log")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	_, err = f.WriteString("[pid 28772] 06:01:23.000001 select(4, [3], NULL, NULL, NULL <unfinished ...>\n[pid 28779] 06:01:23.000002 clock_gettime(CLOCK_REALTIME, {tv_sec=1, tv_nsec=2}) = 0 <0.000003>\n[pid 28772] 06:01:23.000004 <... select resumed> ) = 1 (in [3]) <0.000123>\n")
	if err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close temp file: %v", err)
	}
	res := &Result{Events: make([]Event, 0)}
	r := &Runner{MaxEvents: 10}
	if err := r.readTraceFile(f.Name(), res); err != nil {
		t.Fatalf("readTraceFile: %v", err)
	}
	if len(res.Events) != 2 {
		t.Fatalf("expected 2 events, got %d: %#v", len(res.Events), res.Events)
	}
	if res.Events[1].Syscall != "select" {
		t.Fatalf("expected merged select event, got %s", res.Events[1].Syscall)
	}
	if res.Events[1].PID != 28772 {
		t.Fatalf("expected pid 28772, got %d", res.Events[1].PID)
	}
	if res.Events[1].Duration != 123*time.Microsecond {
		t.Fatalf("expected merged duration 123µs, got %s", res.Events[1].Duration)
	}
}
