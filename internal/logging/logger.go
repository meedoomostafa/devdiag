package logging

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/meedoomostafa/devdiag/internal/redact"
)

// Level represents a log severity.
type Level string

const (
	LevelTrace  Level = "trace"
	LevelDebug  Level = "debug"
	LevelInfo   Level = "info"
	LevelNotice Level = "notice"
	LevelWarn   Level = "warn"
	LevelError  Level = "error"
	LevelFatal  Level = "fatal"
)

var levelOrder = map[Level]int{
	LevelTrace:  0,
	LevelDebug:  1,
	LevelInfo:   2,
	LevelNotice: 3,
	LevelWarn:   4,
	LevelError:  5,
	LevelFatal:  6,
}

// levelRank maps unknown levels to the highest severity instead of the
// zero-value trace rank, so a typo'd level can never bypass min-level
// filtering or silently drop error-class logs.
func levelRank(l Level) int {
	if rank, ok := levelOrder[l]; ok {
		return rank
	}
	return levelOrder[LevelFatal]
}

// Logger writes structured logs to stderr.
type Logger struct {
	mu           sync.Mutex
	out          io.Writer
	minLevel     Level
	redactEngine *redact.Engine
}

// New creates a Logger that writes to stderr.
func New(minLevel Level, engine *redact.Engine) *Logger {
	return &Logger{
		out:          os.Stderr,
		minLevel:     minLevel,
		redactEngine: engine,
	}
}

// log writes a log line if level is sufficient.
func (l *Logger) log(level Level, event string, msg string) {
	if levelRank(level) < levelRank(l.minLevel) {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	// Redact the message before logging
	if l.redactEngine != nil {
		msg = l.redactEngine.RedactString(msg, "log")
	}

	ts := time.Now().UTC().Format(time.RFC3339)
	line := fmt.Sprintf("%s %s event=%s %s\n", ts, levelAbbrev(level), event, msg)
	_, _ = l.out.Write([]byte(line)) // best-effort: stderr write failures are unreportable
}

func levelAbbrev(l Level) string {
	switch l {
	case LevelTrace:
		return "TRC"
	case LevelDebug:
		return "DBG"
	case LevelInfo:
		return "INF"
	case LevelNotice:
		return "NTC"
	case LevelWarn:
		return "WRN"
	case LevelError:
		return "ERR"
	case LevelFatal:
		return "FTL"
	default:
		return "???"
	}
}

// Public log methods
func (l *Logger) Info(event, msg string)  { l.log(LevelInfo, event, msg) }
func (l *Logger) Warn(event, msg string)  { l.log(LevelWarn, event, msg) }
func (l *Logger) Error(event, msg string) { l.log(LevelError, event, msg) }
