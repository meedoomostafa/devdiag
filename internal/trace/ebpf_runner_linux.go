//go:build linux && (amd64 || arm64)

package trace

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
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

	if err := rlimit.RemoveMemlock(); err != nil {
		res.CapabilityEvidence = append(res.CapabilityEvidence,
			TraceEvidence{Source: "ebpf_memlock", Value: "unavailable"},
			TraceEvidence{Source: "ebpf_memlock_error", Value: err.Error()},
		)
		res.TraceUnavailable = true
		res.UnavailableReason = "ebpf_memlock_unavailable"
		res.Notes = append(res.Notes, "ebpf backend unavailable: memlock limit could not be removed")
		return res, nil
	}

	objs := devdiagEbpfObjects{}
	if err := loadDevdiagEbpfObjects(&objs, nil); err != nil {
		res.CapabilityEvidence = append(res.CapabilityEvidence,
			TraceEvidence{Source: "ebpf_load", Value: "failed"},
			TraceEvidence{Source: "ebpf_load_error", Value: err.Error()},
		)
		res.TraceUnavailable = true
		res.UnavailableReason = "ebpf_load_failed"
		res.Notes = append(res.Notes, "ebpf backend unavailable: object load failed")
		return res, nil
	}
	defer objs.Close()

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		res.CapabilityEvidence = append(res.CapabilityEvidence,
			TraceEvidence{Source: "ebpf_ringbuf", Value: "failed"},
			TraceEvidence{Source: "ebpf_ringbuf_error", Value: err.Error()},
		)
		res.TraceUnavailable = true
		res.UnavailableReason = "ebpf_ringbuf_failed"
		res.Notes = append(res.Notes, "ebpf backend unavailable: ring buffer reader failed")
		return res, nil
	}
	defer reader.Close()

	tracepoints := ebpfTracepointsForScopes(scopes)
	attached, err := attachDevdiagEBPFTracepoints(&objs, tracepoints)
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
	defer attached.cleanup()
	res.CapabilityEvidence = append(res.CapabilityEvidence,
		TraceEvidence{Source: "ebpf_attach_mode", Value: attached.mode},
		TraceEvidence{Source: "ebpf_tracepoints_attached", Value: strings.Join(attached.names, ",")},
		TraceEvidence{Source: "ebpf_tracepoint_link_count", Value: fmt.Sprintf("%d", len(attached.links))},
	)

	start := time.Now()
	wrapperArgs := append([]string{"-c", `kill -STOP $$; exec "$@"`, "devdiag-ebpf-wrapper", command}, args...)
	cmd := exec.CommandContext(ctx, "sh", wrapperArgs...)
	err = cmd.Start()
	if err != nil {
		res.Duration = time.Since(start)
		res.ExitCode = -1
		res.ProcessFailed = true
		res.Notes = append(res.Notes, fmt.Sprintf("traced command failed to start: %v", err))
		return res, nil
	}

	rootPID := uint32(cmd.Process.Pid)
	if err := waitForProcessStop(ctx, int(rootPID), 2*time.Second); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		res.Duration = time.Since(start)
		res.ProcessFailed = true
		res.Notes = append(res.Notes, fmt.Sprintf("traced command did not pause for eBPF setup: %v", err))
		return res, nil
	}
	tracked := uint8(1)
	if err := objs.TrackedPids.Put(rootPID, tracked); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		res.Duration = time.Since(start)
		res.TraceUnavailable = true
		res.UnavailableReason = "ebpf_pid_seed_failed"
		res.CapabilityEvidence = append(res.CapabilityEvidence,
			TraceEvidence{Source: "ebpf_pid_seed", Value: "failed"},
			TraceEvidence{Source: "ebpf_pid_seed_error", Value: err.Error()},
		)
		res.Notes = append(res.Notes, "ebpf backend unavailable: root pid could not be seeded")
		return res, nil
	}
	res.CapabilityEvidence = append(res.CapabilityEvidence, TraceEvidence{Source: "ebpf_root_pid", Value: fmt.Sprintf("%d", rootPID)})

	events := readEBPFEvents(reader)
	if err := syscall.Kill(int(rootPID), syscall.SIGCONT); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		res.Duration = time.Since(start)
		res.ProcessFailed = true
		res.Notes = append(res.Notes, fmt.Sprintf("traced command could not resume after eBPF setup: %v", err))
		return res, nil
	}

	err = cmd.Wait()
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
	_ = reader.Close()

	var rawEvents []devdiagEbpfTraceEvent
	notedDecodeError := false
	for item := range events {
		if item.err != nil {
			res.SkippedEvents++
			if !notedDecodeError {
				res.Notes = append(res.Notes, fmt.Sprintf("skipped undecodable ebpf event: %v", item.err))
				notedDecodeError = true
			}
			continue
		}
		rawEvents = append(rawEvents, item.event)
	}
	res.Events = eventsFromEBPFKernelEvents(rawEvents, scopes)
	res.CapabilityEvidence = append(res.CapabilityEvidence,
		TraceEvidence{Source: "ebpf_raw_event_count", Value: fmt.Sprintf("%d", len(rawEvents))},
		TraceEvidence{Source: "ebpf_event_count", Value: fmt.Sprintf("%d", len(res.Events))},
	)
	return res, nil
}

type ebpfReadItem struct {
	event devdiagEbpfTraceEvent
	err   error
}

func readEBPFEvents(reader *ringbuf.Reader) <-chan ebpfReadItem {
	items := make(chan ebpfReadItem, 1024)
	go func() {
		defer close(items)
		for {
			record, err := reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				items <- ebpfReadItem{err: err}
				continue
			}
			var event devdiagEbpfTraceEvent
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				items <- ebpfReadItem{err: err}
				continue
			}
			items <- ebpfReadItem{event: event}
		}
	}()
	return items
}

func waitForProcessStop(ctx context.Context, pid int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		state, err := readLinuxProcessState(pid)
		if err != nil {
			return err
		}
		if strings.HasPrefix(state, "T") || strings.HasPrefix(state, "t") {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("process state %q did not become stopped before timeout", state)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func readLinuxProcessState(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "State:") {
			return strings.TrimSpace(strings.TrimPrefix(line, "State:")), nil
		}
	}
	return "", fmt.Errorf("state not found in /proc/%d/status", pid)
}

type ebpfAttachResult struct {
	links   []link.Link
	names   []string
	mode    string
	cleanup func()
}

func attachDevdiagEBPFTracepoints(objs *devdiagEbpfObjects, tracepoints []string) (*ebpfAttachResult, error) {
	result, err := attachDevdiagPerfTracepoints(objs, tracepoints)
	if err == nil {
		return result, nil
	}
	rawResult, rawErr := attachDevdiagRawTracepoints(objs, tracepoints)
	if rawErr == nil {
		return rawResult, nil
	}
	return nil, fmt.Errorf("%w; raw_tracepoint fallback failed: %v", err, rawErr)
}

func attachDevdiagPerfTracepoints(objs *devdiagEbpfObjects, tracepoints []string) (*ebpfAttachResult, error) {
	programs := map[string]*ebpf.Program{
		"sched/sched_process_fork":   objs.TracepointSchedProcessFork,
		"syscalls/sys_enter_openat":  objs.TracepointSysEnterOpenat,
		"syscalls/sys_exit_openat":   objs.TracepointSysExitOpenat,
		"syscalls/sys_enter_execve":  objs.TracepointSysEnterExecve,
		"syscalls/sys_exit_execve":   objs.TracepointSysExitExecve,
		"syscalls/sys_enter_connect": objs.TracepointSysEnterConnect,
		"syscalls/sys_exit_connect":  objs.TracepointSysExitConnect,
		"syscalls/sys_enter_bind":    objs.TracepointSysEnterBind,
		"syscalls/sys_exit_bind":     objs.TracepointSysExitBind,
	}
	var links []link.Link
	cleanup := func() {
		for _, lnk := range links {
			_ = lnk.Close()
		}
	}
	for _, tracepoint := range tracepoints {
		prog := programs[tracepoint]
		if prog == nil {
			cleanup()
			return nil, fmt.Errorf("missing ebpf program for tracepoint %q", tracepoint)
		}
		group, name, ok := strings.Cut(tracepoint, "/")
		if !ok {
			cleanup()
			return nil, fmt.Errorf("invalid tracepoint %q", tracepoint)
		}
		lnk, err := link.Tracepoint(group, name, prog, nil)
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("attach %s: %w", tracepoint, err)
		}
		links = append(links, lnk)
	}
	return &ebpfAttachResult{links: links, names: tracepoints, mode: "tracepoint", cleanup: cleanup}, nil
}

func attachDevdiagRawTracepoints(objs *devdiagEbpfObjects, tracepoints []string) (*ebpfAttachResult, error) {
	if len(tracepoints) == 0 {
		return &ebpfAttachResult{cleanup: func() {}, mode: "raw_tracepoint"}, nil
	}
	programs := map[string]*ebpf.Program{
		"raw_tracepoint/sys_enter": objs.RawTracepointSysEnter,
		"raw_tracepoint/sys_exit":  objs.RawTracepointSysExit,
	}
	rawTracepoints := []string{"raw_tracepoint/sys_enter", "raw_tracepoint/sys_exit"}
	var links []link.Link
	cleanup := func() {
		for _, lnk := range links {
			_ = lnk.Close()
		}
	}
	for _, tracepoint := range rawTracepoints {
		prog := programs[tracepoint]
		if prog == nil {
			cleanup()
			return nil, fmt.Errorf("missing ebpf program for tracepoint %q", tracepoint)
		}
		_, name, _ := strings.Cut(tracepoint, "/")
		lnk, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: name, Program: prog})
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("attach %s: %w", tracepoint, err)
		}
		links = append(links, lnk)
	}
	return &ebpfAttachResult{links: links, names: rawTracepoints, mode: "raw_tracepoint", cleanup: cleanup}, nil
}
