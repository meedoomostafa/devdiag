package trace

import (
	"strings"
	"testing"
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
