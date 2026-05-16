package gpu

import (
	"context"
	"encoding/csv"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// GPUDevice represents a single detected GPU.
type GPUDevice struct {
	Index         int
	Name          string
	DriverVersion string
	VRAM_MB       int
}

// GPUInfo is the typed internal representation of GPU state.
type GPUInfo struct {
	Present           bool
	Devices           []GPUDevice
	ModuleLoaded      bool
	SecureBootEnabled *bool // nil = unknown
	HardwareDetected  bool
}

// Collector detects NVIDIA GPU presence and properties.
type Collector struct {
	Runner           cmdrunner.CommandRunner
	procPathChecker  func(string) (os.FileInfo, error)
	modulesReader    func() ([]byte, error)
	secureBootReader func() ([]byte, error)
}

func (c *Collector) Name() string {
	return "gpu"
}

// Collect runs layered GPU detection and returns structured evidence.
func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	if c.Runner == nil {
		c.Runner = cmdrunner.NewRealRunner()
	}
	if c.procPathChecker == nil {
		c.procPathChecker = os.Stat
	}
	if c.modulesReader == nil {
		c.modulesReader = func() ([]byte, error) { return os.ReadFile("/proc/modules") }
	}
	if c.secureBootReader == nil {
		c.secureBootReader = func() ([]byte, error) { return os.ReadFile("/sys/kernel/security/secureboot") }
	}

	info := &GPUInfo{}
	evidence := []schema.Evidence{}
	notes := []string{}
	status := schema.CollectorOK
	partial := false

	// Layer 1: nvidia-smi query
	cmdCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	res := c.Runner.Run(cmdCtx, "nvidia-smi",
		"--query-gpu=index,name,driver_version,memory.total",
		"--format=csv,noheader,nounits")
	cancel()

	if res.TimedOut {
		status = schema.CollectorTimeout
		partial = true
		notes = append(notes, "nvidia-smi timed out")
	} else if res.NotFound {
		// nvidia-smi not available — fall through to layer 2
		notes = append(notes, "nvidia-smi not found")
	} else if res.ExitCode == 0 {
		devices, err := parseNvidiaSMIOutput(res.Stdout)
		if err == nil && len(devices) > 0 {
			info.Present = true
			info.Devices = devices
			info.HardwareDetected = true
		} else if res.Stdout != "" {
			// Command succeeded but parsing failed — partial evidence
			partial = true
			notes = append(notes, "nvidia-smi output parsing failed")
		}
	} else {
		// Non-zero exit — could be driver issue
		partial = true
		notes = append(notes, "nvidia-smi exited with error")
		if res.PermissionDenied {
			status = schema.CollectorPermissionDenied
		}
	}

	// Layer 2: /proc/driver/nvidia/gpus
	if !info.HardwareDetected {
		if _, err := c.procPathChecker("/proc/driver/nvidia/gpus"); err == nil {
			info.HardwareDetected = true
		}
	}

	// Layer 3: optional lspci
	if !info.HardwareDetected {
		cmdCtx, cancel = context.WithTimeout(ctx, 1*time.Second)
		res := c.Runner.Run(cmdCtx, "lspci")
		cancel()
		if res.ExitCode == 0 && strings.Contains(strings.ToLower(res.Stdout), "nvidia") {
			info.HardwareDetected = true
		}
	}

	// Detect module load status
	info.ModuleLoaded = c.moduleLoaded()

	// Detect Secure Boot
	info.SecureBootEnabled = c.secureBootStatus()

	// Flatten typed structs into evidence
	if info.Present {
		evidence = append(evidence, schema.Evidence{Source: "gpu_present", Value: "true"})
		evidence = append(evidence, schema.Evidence{Source: "gpu_count", Value: strconv.Itoa(len(info.Devices))})
		for _, d := range info.Devices {
			prefix := "gpu_" + strconv.Itoa(d.Index) + "_"
			evidence = append(evidence, schema.Evidence{Source: prefix + "name", Value: d.Name})
			evidence = append(evidence, schema.Evidence{Source: prefix + "driver_version", Value: d.DriverVersion})
			evidence = append(evidence, schema.Evidence{Source: prefix + "vram_mb", Value: strconv.Itoa(d.VRAM_MB)})
		}
	} else {
		evidence = append(evidence, schema.Evidence{Source: "gpu_present", Value: "false"})
	}

	if info.HardwareDetected {
		evidence = append(evidence, schema.Evidence{Source: "gpu_hardware_detected", Value: "true"})
	} else {
		evidence = append(evidence, schema.Evidence{Source: "gpu_hardware_detected", Value: "false"})
	}

	if info.ModuleLoaded {
		evidence = append(evidence, schema.Evidence{Source: "gpu_nvidia_module_loaded", Value: "true"})
	} else {
		evidence = append(evidence, schema.Evidence{Source: "gpu_nvidia_module_loaded", Value: "false"})
	}

	if info.SecureBootEnabled != nil {
		val := "false"
		if *info.SecureBootEnabled {
			val = "true"
		}
		evidence = append(evidence, schema.Evidence{Source: "gpu_secure_boot_enabled", Value: val})
	} else {
		evidence = append(evidence, schema.Evidence{Source: "gpu_secure_boot_enabled", Value: "unknown"})
	}

	// Applicable: true if hardware is detected or nvidia-smi works
	applicable := info.Present || info.HardwareDetected

	if !applicable {
		notes = append(notes, "No NVIDIA GPU detected")
	}

	return schema.CollectorResult{
		Name:       c.Name(),
		Status:     status,
		Applicable: &applicable,
		Partial:    partial,
		Evidence:   evidence,
		Notes:      notes,
	}, nil
}

// parseNvidiaSMIOutput parses CSV lines from nvidia-smi --query-gpu.
func parseNvidiaSMIOutput(stdout string) ([]GPUDevice, error) {
	var devices []GPUDevice
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Use encoding/csv to properly handle quoted fields (e.g. GPU names with commas).
		r := csv.NewReader(strings.NewReader(line))
		r.TrimLeadingSpace = true
		parts, err := r.Read()
		if err != nil {
			continue
		}
		if len(parts) < 4 {
			continue
		}
		idx, err := strconv.Atoi(parts[0])
		if err != nil {
			continue
		}
		vram, err := strconv.Atoi(parts[3])
		if err != nil {
			// nounits should give plain integer, but tolerate parse failure
			vram = 0
		}
		devices = append(devices, GPUDevice{
			Index:         idx,
			Name:          parts[1],
			DriverVersion: parts[2],
			VRAM_MB:       vram,
		})
	}
	return devices, nil
}

// moduleLoaded checks /proc/modules for nvidia.
func (c *Collector) moduleLoaded() bool {
	reader := c.modulesReader
	if reader == nil {
		reader = func() ([]byte, error) { return os.ReadFile("/proc/modules") }
	}
	data, err := reader()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "nvidia ") {
			return true
		}
	}
	return false
}

// secureBootStatus reads /sys/kernel/security/secureboot.
func (c *Collector) secureBootStatus() *bool {
	reader := c.secureBootReader
	if reader == nil {
		reader = func() ([]byte, error) { return os.ReadFile("/sys/kernel/security/secureboot") }
	}
	data, err := reader()
	if err != nil {
		return nil
	}
	s := strings.TrimSpace(string(data))
	if s == "1" {
		t := true
		return &t
	}
	if s == "0" {
		f := false
		return &f
	}
	return nil
}
