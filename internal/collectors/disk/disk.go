package disk

import (
	"context"
	"fmt"
	"syscall"

	"github.com/meedoomostafa/devdiag/internal/schema"
)

// Collector checks disk and inode availability for the repo mount.
type Collector struct {
	Path string // mount point to check; defaults to "."
}

func (c *Collector) Name() string {
	return "disk"
}

func (c *Collector) Collect(ctx context.Context) (schema.CollectorResult, error) {
	path := c.Path
	if path == "" {
		path = "."
	}

	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return schema.CollectorResult{
			Name:    c.Name(),
			Status:  schema.CollectorUnavailable,
			Notes:   []string{fmt.Sprintf("statfs failed: %v", err)},
			Partial: true,
		}, nil
	}

	// Calculate free space
	blockSize := uint64(stat.Bsize)
	totalBytes := stat.Blocks * blockSize
	freeBytes := stat.Bavail * blockSize
	freeInodes := stat.Ffree
	totalInodes := stat.Files

	var freeBytesPct, freeInodesPct float64
	if totalBytes > 0 {
		freeBytesPct = float64(freeBytes) / float64(totalBytes) * 100
	}
	if totalInodes > 0 {
		freeInodesPct = float64(freeInodes) / float64(totalInodes) * 100
	}

	evidence := []schema.Evidence{
		{Source: "host_disk_path", Value: path},
		{Source: "host_disk_free_bytes", Value: fmt.Sprintf("%d", freeBytes)},
		{Source: "host_disk_free_pct", Value: fmt.Sprintf("%.1f", freeBytesPct)},
		{Source: "host_disk_total_inodes", Value: fmt.Sprintf("%d", totalInodes)},
		{Source: "host_disk_free_inodes", Value: fmt.Sprintf("%d", freeInodes)},
		{Source: "host_disk_free_inodes_pct", Value: fmt.Sprintf("%.1f", freeInodesPct)},
		{Source: "host_disk_inodes_available", Value: boolStr(totalInodes > 0)},
	}

	return schema.CollectorResult{
		Name:     c.Name(),
		Status:   schema.CollectorOK,
		Evidence: evidence,
	}, nil
}

func boolStr(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
