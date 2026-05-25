//go:build linux && (amd64 || arm64)

package trace

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
)

func RunEBPF(ctx context.Context, scopes []Scope, command string, args ...string) (*Result, error) {
	if command == "" {
		return nil, fmt.Errorf("trace command is empty")
	}
	res := &Result{
		Command: command,
		Args:    args,
		Scopes:  scopes,
		Backend: string(BackendEBPF),
		Events:  []Event{},
	}

	support := checkEBPFSupport(defaultEBPFEnvironment(func() error {
		if err := features.HaveProgramType(ebpf.TracePoint); err != nil {
			return errEBPFFeatureUnavailable(err.Error())
		}
		return nil
	}))
	res.CapabilityEvidence = append(res.CapabilityEvidence, support.Evidence...)
	if !support.Supported {
		res.TraceUnavailable = true
		res.UnavailableReason = support.Reason
		res.Notes = append(res.Notes, "ebpf backend unavailable: "+support.Reason)
		return res, nil
	}

	tracepoints := ebpfTracepointsForScopes(scopes)
	links, cleanup, err := attachEBPFTracepoints(tracepoints)
	if err != nil {
		res.CapabilityEvidence = append(res.CapabilityEvidence,
			TraceEvidence{Source: "ebpf_tracepoint_attach", Value: "failed"},
			TraceEvidence{Source: "ebpf_tracepoint_attach_error", Value: err.Error()},
		)
		res.TraceUnavailable = true
		res.UnavailableReason = "ebpf_tracepoint_attach_failed"
		res.Notes = append(res.Notes, "ebpf backend unavailable: tracepoint attach failed")
		return res, nil
	}
	defer cleanup()
	res.CapabilityEvidence = append(res.CapabilityEvidence,
		TraceEvidence{Source: "ebpf_tracepoints_attached", Value: strings.Join(tracepoints, ",")},
		TraceEvidence{Source: "ebpf_tracepoint_link_count", Value: fmt.Sprintf("%d", len(links))},
	)

	start := time.Now()
	cmd := exec.CommandContext(ctx, command, args...)
	err = cmd.Run()
	res.Duration = time.Since(start)
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			res.ProcessFailed = true
			res.Notes = append(res.Notes, fmt.Sprintf("traced process killed by signal %d (%s)", ws.Signal(), ws.Signal()))
		}
	} else if err != nil {
		res.ExitCode = -1
	}
	if ctx.Err() != nil {
		res.Canceled = true
		res.Partial = true
		res.Notes = append(res.Notes, "trace canceled by parent context")
	}
	if err != nil {
		if _, ok := err.(*exec.ExitError); ok {
			res.ProcessFailed = true
			res.Notes = append(res.Notes, "traced command exited non-zero")
		} else if ctx.Err() == nil {
			res.ProcessFailed = true
			res.Notes = append(res.Notes, fmt.Sprintf("traced command failed: %v", err))
		}
	}
	return res, nil
}

func attachEBPFTracepoints(tracepoints []string) ([]link.Link, func(), error) {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name:    "devdiag_trace_probe",
		Type:    ebpf.TracePoint,
		License: "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		return nil, func() {}, err
	}
	var links []link.Link
	cleanup := func() {
		for _, lnk := range links {
			_ = lnk.Close()
		}
		_ = prog.Close()
	}
	for _, tracepoint := range tracepoints {
		group, name, ok := strings.Cut(tracepoint, "/")
		if !ok {
			cleanup()
			return nil, func() {}, fmt.Errorf("invalid tracepoint %q", tracepoint)
		}
		lnk, err := link.Tracepoint(group, name, prog, nil)
		if err != nil {
			cleanup()
			return nil, func() {}, fmt.Errorf("attach %s: %w", tracepoint, err)
		}
		links = append(links, lnk)
	}
	return links, cleanup, nil
}
