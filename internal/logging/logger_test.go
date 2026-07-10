package logging

import (
	"strings"
	"testing"

	"github.com/meedoomostafa/devdiag/internal/redact"
)

func testEngine() *redact.Engine {
	return redact.NewEngine(redact.LevelDefault)
}

func TestLevelRank_KnownLevelsOrdered(t *testing.T) {
	ordered := []Level{LevelTrace, LevelDebug, LevelInfo, LevelNotice, LevelWarn, LevelError, LevelFatal}
	for i := 1; i < len(ordered); i++ {
		if levelRank(ordered[i-1]) >= levelRank(ordered[i]) {
			t.Fatalf("levelRank(%s) >= levelRank(%s)", ordered[i-1], ordered[i])
		}
	}
}

func TestLevelRank_UnknownLevelIsHighestSeverity(t *testing.T) {
	if got := levelRank(Level("bogus")); got != levelRank(LevelFatal) {
		t.Fatalf("levelRank(bogus) = %d, want fatal rank %d", got, levelRank(LevelFatal))
	}
}

func TestLogger_FiltersBelowMinLevel(t *testing.T) {
	var sb strings.Builder
	l := New(LevelWarn, nil)
	l.out = &sb

	l.Info("test", "should be filtered")
	l.Warn("test", "should appear")

	out := sb.String()
	if strings.Contains(out, "should be filtered") {
		t.Errorf("info line leaked through warn min level: %q", out)
	}
	if !strings.Contains(out, "should appear") {
		t.Errorf("warn line missing: %q", out)
	}
}

func TestLogger_RedactsMessages(t *testing.T) {
	var sb strings.Builder
	l := New(LevelInfo, testEngine())
	l.out = &sb

	l.Info("test", "API_KEY=secret123")
	if strings.Contains(sb.String(), "secret123") {
		t.Errorf("secret leaked into log output: %q", sb.String())
	}
}
