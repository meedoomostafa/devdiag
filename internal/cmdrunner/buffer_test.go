package cmdrunner

import (
	"testing"
)

func TestCappedBuffer(t *testing.T) {
	tests := []struct {
		name          string
		cap           int
		writes        []string
		wantString    string
		wantSeen      int
		wantTruncated bool
	}{
		{
			name:       "exact cap",
			cap:        5,
			writes:     []string{"hello"},
			wantString: "hello",
			wantSeen:   5,
		},
		{
			name:          "over cap single write",
			cap:           5,
			writes:        []string{"hello world"},
			wantString:    "hello" + TruncationMarker,
			wantSeen:      11,
			wantTruncated: true,
		},
		{
			name:          "over cap multiple writes",
			cap:           5,
			writes:        []string{"hel", "lo", " world"},
			wantString:    "hello" + TruncationMarker,
			wantSeen:      11,
			wantTruncated: true,
		},
		{
			name:          "already full",
			cap:           3,
			writes:        []string{"abc", "def"},
			wantString:    "abc" + TruncationMarker,
			wantSeen:      6,
			wantTruncated: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewCappedBuffer(tt.cap)
			for _, w := range tt.writes {
				n, err := b.Write([]byte(w))
				if err != nil {
					t.Fatalf("Write() error = %v", err)
				}
				if n != len(w) {
					t.Errorf("Write() n = %d, want %d", n, len(w))
				}
			}

			if got := b.String(); got != tt.wantString {
				t.Errorf("String() = %q, want %q", got, tt.wantString)
			}
			if got := b.Seen(); got != tt.wantSeen {
				t.Errorf("Seen() = %d, want %d", got, tt.wantSeen)
			}
			if got := b.Truncated(); got != tt.wantTruncated {
				t.Errorf("Truncated() = %v, want %v", got, tt.wantTruncated)
			}
		})
	}
}
