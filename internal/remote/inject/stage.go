package inject

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/meedoomostafa/devdiag/internal/remote/profile"
)

// Stage builds a local temporary directory containing the profile files.
// It returns the staging directory path and a list of written file paths.
func Stage(p *profile.RemoteProfile) (string, []string, error) {
	dir, err := os.MkdirTemp("", "devdiag-remote-*")
	if err != nil {
		return "", nil, fmt.Errorf("create staging dir: %w", err)
	}

	var written []string
	for _, f := range p.Files {
		localPath := filepath.Join(dir, f.TargetPath)
		if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
			return dir, written, fmt.Errorf("mkdir %s: %w", filepath.Dir(localPath), err)
		}
		if err := os.WriteFile(localPath, []byte(f.Content), parseMode(f.Mode)); err != nil {
			return dir, written, fmt.Errorf("write %s: %w", localPath, err)
		}
		written = append(written, localPath)
	}

	return dir, written, nil
}

func parseMode(s string) os.FileMode {
	if s == "" {
		return 0644
	}
	var m uint32
	fmt.Sscanf(s, "%o", &m)
	if m == 0 {
		return 0644
	}
	return os.FileMode(m)
}
