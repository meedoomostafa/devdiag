//go:build linux && (amd64 || arm64)

package trace

import "context"

func RunEBPF(ctx context.Context, scopes []Scope, command string, args ...string) (*Result, error) {
	return newEBPFUnavailableResult(scopes, command, args, "ebpf_not_implemented_for_m7"), nil
}
