package audit

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
)

// FileName is the audit file inside the state directory. The name is fixed,
// so the caller never supplies a file path.
const FileName = "audit.jsonl"

// Open creates dir if needed and returns a Log that appends to
// dir/audit.jsonl. The file is never read back. An existing file with a mode
// broader than 0600 is tightened to 0600 (Unix only).
//
// Confinement: the file name is a constant, so the caller chooses only the
// directory, and a symlinked directory is followed on purpose (it is the
// operator's own state directory). The file itself is checked on the real
// file system, not by its text: an existing entry with that name must be a
// regular file, not a symlink or anything else, so the log cannot be
// redirected elsewhere. There is a small window between the check and the
// open; closing it would need O_NOFOLLOW, which Windows does not have, and
// the state directory is owned by the user who runs tailkeep.
func Open(dir string, logger *slog.Logger) (*Log, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("audit directory: %w", err)
	}
	path := filepath.Join(dir, FileName)
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("audit file %s is not a regular file", FileName)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit file: %w", err)
	}
	if err := keepPrivate(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("audit file mode: %w", err)
	}
	return New(f, logger), nil
}

// keepPrivate tightens an existing audit file that other users can read or
// write down to 0600. It works on the open file, so the file checked is the
// file changed. Windows does not enforce Unix mode bits, so nothing is done
// there; the state directory's own access rules apply.
func keepPrivate(f *os.File) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 == 0 {
		return nil
	}
	return f.Chmod(0o600)
}
