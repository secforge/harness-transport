package codexmsg

import (
	"fmt"
	"os"
	"path/filepath"
)

// Where the daemon lives. Two sockets exist under a Codex home and they are
// easy to confuse: ipc/ipc.sock is the IDE-context channel, which carries
// workspace context between the TUI and an editor extension and has nothing to
// do with sessions. The one that matters here is the control socket.
const (
	controlDirName    = "app-server-control"
	controlSocketName = "app-server-control.sock"
	startupLockName   = "app-server-startup.lock"
)

// maxUnixPath is the AF_UNIX sun_path limit on Linux, including the trailing
// NUL. A Codex home deep enough to push the socket past it makes the CLI fall
// back to an embedded app server instead of sharing the daemon — so a path
// that is merely long changes which server you are talking to, silently.
const maxUnixPath = 108

// Home returns the Codex home directory: $CODEX_HOME, else ~/.codex.
func Home() (string, error) {
	if h := os.Getenv("CODEX_HOME"); h != "" {
		return h, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find home directory: %w", err)
	}
	return filepath.Join(home, ".codex"), nil
}

// ControlSocketPath returns the daemon's control socket under a Codex home.
func ControlSocketPath(codexHome string) string {
	return filepath.Join(codexHome, controlDirName, controlSocketName)
}

// StartupLockPath returns the lock file beside the control socket, held while
// a daemon is starting.
func StartupLockPath(codexHome string) string {
	return filepath.Join(codexHome, controlDirName, startupLockName)
}

// DefaultSocket resolves the control socket for the current environment and
// checks that it is usable.
func DefaultSocket() (string, error) {
	home, err := Home()
	if err != nil {
		return "", err
	}
	path := ControlSocketPath(home)
	if err := CheckSocketPath(path); err != nil {
		return "", err
	}
	return path, nil
}

// CheckSocketPath reports why a control socket cannot be used: too long to
// bind, or absent because no daemon is running.
func CheckSocketPath(path string) error {
	if len(path)+1 > maxUnixPath {
		return fmt.Errorf("socket path is %d bytes, over the %d byte AF_UNIX limit: %s "+
			"(a Codex home this deep makes the CLI use an embedded app server instead of the daemon)",
			len(path), maxUnixPath-1, path)
	}
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		return fmt.Errorf("no app-server daemon socket at %s; start one (any codex command that "+
			"uses the shared daemon will) and try again", path)
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("%s is not a socket", path)
	}
	return nil
}
