//go:build !linux || !(amd64 || arm64)

package trace

import "context"

func RunEBPF(ctx context.Context, scopes []Scope, command string, args ...string) (*Result, error) {
	res := newEBPFUnavailableResult(scopes, command, args, "unsupported_platform")
	res.CapabilityEvidence = append(res.CapabilityEvidence, TraceEvidence{Source: "ebpf_platform", Value: "unsupported"})
	return res, nil
}
