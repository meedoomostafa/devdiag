package cmdrunner

import (
	"strings"
	"sync"
)

const TruncationMarker = "\n... [output truncated]"

// CappedBuffer is a thread-safe io.Writer that limits total captured bytes.
type CappedBuffer struct {
	mu        sync.Mutex
	buf       strings.Builder
	cap       int
	seen      int
	truncated bool
}

func NewCappedBuffer(cap int) *CappedBuffer {
	if cap <= 0 {
		cap = maxCaptureBytes
	}
	return &CappedBuffer{cap: cap}
}

func (c *CappedBuffer) Write(p []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	n = len(p)
	c.seen += n

	if c.truncated {
		return n, nil
	}

	currentLen := c.buf.Len()
	remaining := c.cap - currentLen

	if remaining <= 0 {
		c.truncated = true
		return n, nil
	}

	if len(p) > remaining {
		c.buf.Write(p[:remaining])
		c.truncated = true
	} else {
		c.buf.Write(p)
	}

	return n, nil
}

func (c *CappedBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.buf.String()
	if c.truncated {
		s += TruncationMarker
	}
	return s
}

func (c *CappedBuffer) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Len()
}

func (c *CappedBuffer) Seen() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seen
}

func (c *CappedBuffer) Truncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.truncated
}
