package updater

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
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

	// Exclusive per-target lock: two concurrent updaters must not
	// interleave backup/stage/rename and corrupt each other's rollback
	// state. O_EXCL creation is the lock; a stale lock older than an hour
	// is broken (a crashed updater cannot hold updates hostage forever).
	lockPath := targetPath + ".update-lock"
	unlock, lerr := acquireLock(lockPath)
	if lerr != nil {
		return lerr
	}
	defer unlock()

	// Preserve the installed binary's mode: a 0700 install must not come
	// back world-executable after an update.
	mode := os.FileMode(0o755)
	backupPath := targetPath + ".old"
	backedUp := false
	if fi, serr := os.Stat(targetPath); serr == nil {
		mode = fi.Mode().Perm()
		if berr := copyFileSyncMode(targetPath, backupPath, mode); berr != nil {
			return fmt.Errorf("create rollback backup: %w", berr)
		}
		backedUp = true
	}

	stagedPath := targetPath + ".new"
	if cerr := copyFileSyncMode(newBinaryPath, stagedPath, mode); cerr != nil {
		return fmt.Errorf("stage new binary: %w", cerr)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(stagedPath)
			if backedUp {
				// Roll back by COPY so devdiag.old itself survives as a
				// recovery point even if this restore is interrupted, and
				// fsync so the recovered binary is durable.
				if cerr := copyFileSyncMode(backupPath, targetPath, mode); cerr != nil {
					err = fmt.Errorf("%w; ROLLBACK ALSO FAILED (%v) - restore manually from %s", err, cerr, backupPath)
					return
				}
				_ = syncDir(dir)
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

// acquireLock creates lockPath exclusively and returns an unlock func.
func acquireLock(lockPath string) (func(), error) {
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(lockPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err == nil {
			_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
			_ = f.Close()
			return func() { _ = os.Remove(lockPath) }, nil
		}
		if !os.IsExist(err) {
			return nil, fmt.Errorf("acquire update lock: %w", err)
		}
		if fi, serr := os.Stat(lockPath); serr == nil && time.Since(fi.ModTime()) > time.Hour {
			_ = os.Remove(lockPath) // stale lock from a crashed updater
			continue
		}
		return nil, fmt.Errorf("another devdiag update appears to be in progress (lock: %s); retry later or remove the lock if no update is running", lockPath)
	}
	return nil, fmt.Errorf("could not acquire update lock at %s", lockPath)
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

// copyFileSyncMode copies src to dst with the given mode and fsyncs.
func copyFileSyncMode(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
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
