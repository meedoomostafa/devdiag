package cache

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/meedoomostafa/devdiag/internal/cmdrunner"
	"github.com/meedoomostafa/devdiag/internal/schema"
)

// CacheEntry represents a single discovered cache location.
type CacheEntry struct {
	Tool     string
	Path     string
	SizeMB   string
	Writable bool
	OwnerUID int
}

// CacheInfo groups all discovered cache entries.
type CacheInfo struct {
	Entries []CacheEntry
}

// Collector analyzes package and build caches without mutating them.
type Collector struct {
	Runner   cmdrunner.CommandRunner
	RepoRoot string
	homeDir  string // overridable for tests
}

func (c *Collector) Name() string {
	return "cache"
}

// Collect inspects known cache directories and reports metadata.
func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	if c.Runner == nil {
		c.Runner = cmdrunner.NewRealRunner()
	}
	if c.homeDir == "" {
		home, _ := os.UserHomeDir()
		c.homeDir = home
	}

	info := &CacheInfo{}
	evidence := []schema.Evidence{}
	notes := []string{}
	status := schema.CollectorOK
	partial := false

	// pip
	if p := c.pipCachePath(); p != "" {
		if e := c.inspectCache(ctx, "pip", p); e != nil {
			info.Entries = append(info.Entries, *e)
		}
	}

	// uv
	if e := c.inspectCache(ctx, "uv", filepath.Join(c.homeDir, ".cache", "uv")); e != nil {
		info.Entries = append(info.Entries, *e)
	}

	// poetry
	if e := c.inspectCache(ctx, "poetry", filepath.Join(c.homeDir, ".cache", "pypoetry")); e != nil {
		info.Entries = append(info.Entries, *e)
	}

	// npm (conditional on repo having package.json)
	if c.hasRepoFile("package.json") {
		if e := c.inspectCache(ctx, "npm", filepath.Join(c.homeDir, ".npm")); e != nil {
			info.Entries = append(info.Entries, *e)
		}
	}

	// pnpm
	for _, p := range []string{
		filepath.Join(c.homeDir, ".local", "share", "pnpm"),
		filepath.Join(c.homeDir, ".pnpm-store"),
	} {
		if exists(p) {
			if e := c.inspectCache(ctx, "pnpm", p); e != nil {
				info.Entries = append(info.Entries, *e)
			}
			break
		}
	}

	// go (conditional on repo having go.mod)
	if c.hasRepoFile("go.mod") {
		goCache := os.Getenv("GOCACHE")
		if goCache == "" {
			goCache = filepath.Join(c.homeDir, ".cache", "go-build")
		}
		if e := c.inspectCache(ctx, "go", goCache); e != nil {
			info.Entries = append(info.Entries, *e)
		}
	}

	// docker
	if e := c.inspectDockerCache(ctx); e != nil {
		info.Entries = append(info.Entries, *e)
	}

	// Flatten evidence
	for _, e := range info.Entries {
		prefix := "cache_" + e.Tool + "_"
		evidence = append(evidence, schema.Evidence{Source: prefix + "path", Value: e.Path})
		evidence = append(evidence, schema.Evidence{Source: prefix + "size_mb", Value: e.SizeMB})
		evidence = append(evidence, schema.Evidence{Source: prefix + "writable", Value: strconv.FormatBool(e.Writable)})
		evidence = append(evidence, schema.Evidence{Source: prefix + "owner_uid", Value: strconv.Itoa(e.OwnerUID)})
	}

	applicable := len(info.Entries) > 0
	if !applicable {
		notes = append(notes, "no caches detected")
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

func (c *Collector) pipCachePath() string {
	if d := os.Getenv("PIP_CACHE_DIR"); d != "" {
		return d
	}
	for _, p := range []string{
		filepath.Join(c.homeDir, ".cache", "pip"),
		filepath.Join(c.homeDir, ".local", "share", "pip"),
	} {
		if exists(p) {
			return p
		}
	}
	return ""
}

func (c *Collector) hasRepoFile(name string) bool {
	if c.RepoRoot == "" {
		return false
	}
	return exists(filepath.Join(c.RepoRoot, name))
}

// inspectCache checks a single cache path for size, ownership, and writability.
// It never creates or modifies files.
func (c *Collector) inspectCache(ctx context.Context, tool, path string) *CacheEntry {
	if !exists(path) {
		return nil
	}

	entry := &CacheEntry{
		Tool: tool,
		Path: path,
	}

	// Ownership and writability via read-only stat
	stat, err := os.Stat(path)
	if err == nil {
		if sys, ok := stat.Sys().(*syscall.Stat_t); ok {
			entry.OwnerUID = int(sys.Uid)
		}
		// Simple writability heuristic: owner-write bit and matching UID,
		// or root (UID 0) who can write anything.
		mode := stat.Mode().Perm()
		uid := os.Getuid()
		entry.Writable = uid == 0 || ((mode&0200 != 0) && entry.OwnerUID == uid)
	}

	// Size via du -sb with 1s timeout
	cmdCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	res := c.Runner.Run(cmdCtx, "du", "-sb", path)
	cancel()

	if res.ExitCode == 0 {
		parts := strings.Fields(res.Stdout)
		if len(parts) > 0 {
			if bytes, err := strconv.ParseInt(parts[0], 10, 64); err == nil {
				entry.SizeMB = strconv.FormatInt(bytes/(1024*1024), 10)
			} else {
				entry.SizeMB = "unknown"
			}
		}
	} else {
		entry.SizeMB = "unknown"
	}

	return entry
}

// inspectDockerCache uses docker system df to report Docker cache size.
// It prefers JSON format when available and falls back to defensive tabular parsing.
func (c *Collector) inspectDockerCache(ctx context.Context) *CacheEntry {
	// Try modern JSON format first
	cmdCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	res := c.Runner.Run(cmdCtx, "docker", "system", "df", "--format", "json")
	cancel()

	if res.ExitCode == 0 && res.Stdout != "" {
		if size := parseDockerSystemDfJSON(res.Stdout); size != "" {
			return &CacheEntry{
				Tool:     "docker",
				Path:     "docker_system",
				SizeMB:   size,
				Writable: true,
				OwnerUID: 0,
			}
		}
	}

	// Fall back to tabular format
	cmdCtx, cancel = context.WithTimeout(ctx, 1500*time.Millisecond)
	res = c.Runner.Run(cmdCtx, "docker", "system", "df")
	cancel()

	if res.ExitCode != 0 {
		return nil
	}

	return parseDockerSystemDfTabular(res.Stdout)
}

// parseDockerSystemDfJSON parses the JSON-lines output from docker system df --format json.
func parseDockerSystemDfJSON(stdout string) string {
	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var obj struct {
			Type string `json:"Type"`
			Size string `json:"Size"`
		}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}
		if obj.Type == "Images" && obj.Size != "" {
			return obj.Size
		}
	}
	return ""
}

// parseDockerSystemDfTabular parses the human-readable docker system df output defensively.
func parseDockerSystemDfTabular(stdout string) *CacheEntry {
	// Expected format:
	// TYPE            TOTAL   ACTIVE  SIZE      RECLAIMABLE
	// Images          10      5       2.5GB     1.2GB
	lines := strings.Split(stdout, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		// Match rows starting with Images or Local Volumes
		first := fields[0]
		if first == "Images" || first == "Local" || first == "Volumes" {
			// Defensive: require at least 4 columns; SIZE is the 4th (index 3) for Images
			// For "Local Volumes" split into two fields, we need at least 5 columns
			idx := 3
			if first == "Local" && len(fields) > 1 && fields[1] == "Volumes" {
				idx = 4
			}
			if len(fields) > idx {
				return &CacheEntry{
					Tool:     "docker",
					Path:     "docker_system",
					SizeMB:   fields[idx],
					Writable: true,
					OwnerUID: 0,
				}
			}
		}
	}
	return nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
