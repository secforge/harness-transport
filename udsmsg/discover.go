package udsmsg

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SocketDirs returns the standard socket directories in probe order. Only the
// ones that could exist on this platform are listed; callers should skip any
// that fail CheckDir.
func SocketDirs() []string {
	uid := os.Getuid()
	dirs := []string{}
	if runtime := os.Getenv("XDG_RUNTIME_DIR"); runtime != "" {
		dirs = append(dirs, filepath.Join(runtime, "cc-socks"))
	}
	dirs = append(dirs,
		fmt.Sprintf("/run/user/%d/cc-socks", uid),
		fmt.Sprintf("/tmp/cc-socks-%d", uid),
		"/tmp/cc-socks",
		fmt.Sprintf("/private/tmp/cc-socks-%d", uid),
		"/private/tmp/cc-socks",
		"/data/data/com.termux/files/usr/tmp/cc-socks",
	)
	return dedup(dirs)
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// FindSocket returns the bound inbox of a session by pid.
func FindSocket(pid int) (string, error) {
	for _, dir := range SocketDirs() {
		if err := CheckDir(dir); err != nil {
			continue
		}
		p := filepath.Join(dir, fmt.Sprintf("%d.sock", pid))
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no socket for pid %d in %s", pid, strings.Join(SocketDirs(), ", "))
}

// Target is a resolved send destination: where to connect, and the token to
// present. Token is empty when no key file was published, which is acceptable
// in the default configuration where auth is optional.
type Target struct {
	PID        int
	SocketPath string
	Token      string
	ProcStart  string
	// Unauthenticated dials without presenting a token. It has to be asked
	// for by name: a receiver that requires authentication destroys such a
	// connection and says nothing, so an omitted token must never be
	// something a caller can do by forgetting. See Dial.
	Unauthenticated bool
}

// ResolveTarget locates a session's inbox and the token published for it.
func ResolveTarget(pid int) (Target, error) {
	path, err := FindSocket(pid)
	if err != nil {
		return Target{}, err
	}
	t := Target{PID: pid, SocketPath: path}
	k, err := ReadKey(pid, path)
	if err != nil {
		return t, fmt.Errorf("read key for pid %d: %w", pid, err)
	}
	if k != nil {
		t.Token, t.ProcStart = k.PeerToken, k.ProcStart
	}
	// Reaching our OWN parent uses the credential that session handed us:
	// it arrives in the environment, needs no key file, and is the one
	// credential we hold that was given rather than found.
	if env := os.Getenv(EnvMessagingSocket); env != "" && env == path {
		if child := os.Getenv(EnvMessagingToken); child != "" {
			t.Token = child
		}
	}
	return t, nil
}

// Environment a session exports to everything it spawns. The names are the
// harness's own and are kept verbatim; they are interface, not our choice.
const (
	EnvMessagingSocket = "CLAUDE_CODE_MESSAGING_SOCKET"
	EnvMessagingToken  = "CLAUDE_CODE_MESSAGING_TOKEN"
)
