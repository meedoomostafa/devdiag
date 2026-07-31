package redact

import (
	"strings"
	"testing"
)

// benchLog builds a log of the size capsule.go redacts wholesale, mixing
// assignments that are masked, assignments that are declined, and plain text.
func benchLog(lines int) string {
	var b strings.Builder
	for i := 0; i < lines; i++ {
		switch i % 4 {
		case 0:
			b.WriteString("2026-01-01T00:00:00Z level=info msg=\"starting worker\" attempt=3\n")
		case 1:
			b.WriteString("API_TOKEN=sk-live-0123456789abcdef DB_PASSWORD=hunter2\n")
		case 2:
			b.WriteString("exit_code=0 duration_ms=1234 path=/var/lib/app/cache\n")
		default:
			b.WriteString("plain diagnostic line with no assignments at all\n")
		}
	}
	return b.String()
}

func BenchmarkRedactStringLog(b *testing.B) {
	for _, lines := range []int{100, 10000} {
		input := benchLog(lines)
		for _, lvl := range []Level{LevelDefault, LevelStrict} {
			b.Run(string(lvl)+"/"+itoa(len(input)/1024)+"KiB", func(b *testing.B) {
				e := NewEngine(lvl)
				b.SetBytes(int64(len(input)))
				b.ReportAllocs()
				for i := 0; i < b.N; i++ {
					_ = e.RedactString(input, "bench")
				}
			})
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}
