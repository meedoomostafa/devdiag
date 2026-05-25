//go:build linux && (amd64 || arm64)

package trace

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go@v0.21.0 -go-package trace -cc clang -no-strip -tags linux -target bpfel -type trace_event devdiagEbpf ebpf_trace.bpf.c
