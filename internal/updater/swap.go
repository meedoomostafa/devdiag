package updater

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// SwapBinary atomically replaces targetPath with newBinaryPath:
//
//  1. the current binary is copied to devdiag.old (fsynced) as a rollback
//     point,
//  2. the new binary is staged as devdiag.new on the SAME filesystem,
//  3. devdiag.new is renamed over the target (atomic on Linux; the running
//     process keeps its old inode, so no ETXTBSY),
//  4. the containing directory is fsynced.
//
// Symlinked targets are refused: renaming over a symlink replaces the link,
// not the binary it points to, which is never what the user meant.
// Unwritable directories produce a clear refusal; the updater never
// escalates privileges.
func SwapBinary(newBinaryPath, targetPath string) (err error) {
	dir := filepath.Dir(targetPath)

	if fi, lerr := os.Lstat(targetPath); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
		resolved, rerr := filepath.EvalSymlinks(targetPath)
		if rerr != nil {
			resolved = "<unresolvable>"
		}
		return fmt.Errorf("%s is a symlink to %s; update the real binary path instead", targetPath, resolved)
	}

	if werr := checkWritable(dir); werr != nil {
		return fmt.Errorf("cannot write to %s: %v; re-run from a user with write access or reinstall to a user-writable directory with scripts/install.sh", dir, werr)
	}

	backupPath := targetPath + ".old"
	backedUp := false
	if _, serr := os.Stat(targetPath); serr == nil {
		if berr := copyFileSync(targetPath, backupPath); berr != nil {
			return fmt.Errorf("create rollback backup: %w", berr)
		}
		backedUp = true
	}

	stagedPath := targetPath + ".new"
	if cerr := copyFileSync(newBinaryPath, stagedPath); cerr != nil {
		return fmt.Errorf("stage new binary: %w", cerr)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(stagedPath)
			if backedUp {
				// Roll back: the backup still holds the previous binary.
				_ = os.Rename(backupPath, targetPath)
			}
		}
	}()

	if rerr := os.Rename(stagedPath, targetPath); rerr != nil {
		return fmt.Errorf("swap binary into place: %w", rerr)
	}
	if derr := syncDir(dir); derr != nil {
		return fmt.Errorf("sync install directory: %w", derr)
	}
	return nil
}

func checkWritable(dir string) error {
	probe, err := os.CreateTemp(dir, ".devdiag-write-probe-*")
	if err != nil {
		return err
	}
	name := probe.Name()
	_ = probe.Close()
	return os.Remove(name)
}

// copyFileSync copies src to dst (0755) and fsyncs the result.
func copyFileSync(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
