package network

import (
	"context"
	"os"
	"strings"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Collector collects local network metadata only (no external connectivity checks in default mode).
type Collector struct{}

func (c *Collector) Name() string {
	return "network"
}

func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	evidence := []schema.Evidence{}

	// Proxy env vars (values redacted)
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		if v := os.Getenv(key); v != "" {
			evidence = append(evidence, schema.Evidence{
				Source: "host_proxy_env",
				Value:  key + "=set",
			})
		}
	}

	// NO_PROXY hints
	if v := os.Getenv("NO_PROXY"); v != "" {
		hosts := strings.Split(v, ",")
		var hints []string
		for _, h := range hosts {
			h = strings.TrimSpace(h)
			if h != "" {
				hints = append(hints, h)
			}
		}
		if len(hints) > 0 {
			evidence = append(evidence, schema.Evidence{
				Source: "host_no_proxy",
				Value:  strings.Join(hints, ", "),
			})
		}
	}

	return schema.CollectorResult{
		Name:     c.Name(),
		Status:   schema.CollectorOK,
		Evidence: evidence,
	}, nil
}
