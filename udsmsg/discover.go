package udsmsg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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

// Session is one discovered session: a live inbox, a registry entry, or both.
// A session with SocketPath == "" has a registry entry but no bound inbox; one
// with SessionID == "" has an inbox but no readable registry entry.
type Session struct {
	PID          int      `json:"pid"`
	SessionID    string   `json:"sessionId,omitempty"`
	Name         string   `json:"name,omitempty"`
	NameSource   string   `json:"nameSource,omitempty"`
	CWD          string   `json:"cwd,omitempty"`
	Status       string   `json:"status,omitempty"`
	Version      string   `json:"version,omitempty"`
	Tmux         string   `json:"tmux,omitempty"`
	Kind         string   `json:"kind,omitempty"`
	Entrypoint   string   `json:"entrypoint,omitempty"`
	ProcStart    string   `json:"procStart,omitempty"`
	PIDDomain    string   `json:"pidDomain,omitempty"`
	PeerFeatures []string `json:"peerFeatures,omitempty"`
	StartedAt    int64    `json:"startedAt,omitempty"`
	UpdatedAt    int64    `json:"updatedAt,omitempty"`

	// SocketPath is the bound inbox, empty when no socket exists.
	SocketPath string `json:"messagingSocketPath,omitempty"`
	// HasKey reports whether a key file exists for SocketPath, i.e. whether
	// we can authenticate rather than send unauthenticated.
	HasKey bool `json:"-"`
	// Live reports whether the pid is running with the recorded start time.
	Live bool `json:"-"`
}

// registryEntry mirrors ~/.claude/sessions/<pid>.json.
type registryEntry struct {
	PID                 int      `json:"pid"`
	SessionID           string   `json:"sessionId"`
	Name                string   `json:"name"`
	NameSource          string   `json:"nameSource"`
	CWD                 string   `json:"cwd"`
	Status              string   `json:"status"`
	Version             string   `json:"version"`
	Tmux                string   `json:"tmux"`
	Kind                string   `json:"kind"`
	Entrypoint          string   `json:"entrypoint"`
	ProcStart           string   `json:"procStart"`
	PIDDomain           string   `json:"pidDomain"`
	PeerFeatures        []string `json:"peerFeatures"`
	StartedAt           int64    `json:"startedAt"`
	UpdatedAt           int64    `json:"updatedAt"`
	MessagingSocketPath string   `json:"messagingSocketPath"`
}

// Discover joins the live inboxes in the socket directories with the session
// registry, and checks liveness against /proc. Sessions are returned sorted by
// pid. A registry entry whose process is gone is reported with Live == false
// rather than omitted, so a stale entry is visible rather than silent.
func Discover() ([]Session, error) {
	byPID := map[int]*Session{}

	// Live inboxes are authoritative for "something is listening".
	for _, dir := range SocketDirs() {
		if err := CheckDir(dir); err != nil {
			continue
		}
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			name := e.Name()
			if !ValidSocketName(name) {
				continue
			}
			pid, ok := PIDFromSocketName(name)
			if !ok {
				continue // opaque 16-hex id, no pid to join on
			}
			path := filepath.Join(dir, name)
			s, seen := byPID[pid]
			if !seen {
				s = &Session{PID: pid}
				byPID[pid] = s
			}
			if s.SocketPath == "" {
				s.SocketPath = path
			}
		}
	}

	// The registry supplies names, cwd and status.
	ents, err := os.ReadDir(SessionsDir())
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	for _, e := range ents {
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSuffix(name, ".json"))
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(SessionsDir(), name))
		if err != nil {
			continue
		}
		var r registryEntry
		if err := json.Unmarshal(b, &r); err != nil {
			continue
		}
		s, seen := byPID[pid]
		if !seen {
			s = &Session{PID: pid}
			byPID[pid] = s
		}
		s.SessionID, s.Name, s.NameSource = r.SessionID, r.Name, r.NameSource
		s.CWD, s.Status, s.Version, s.Tmux = r.CWD, r.Status, r.Version, r.Tmux
		s.Kind, s.Entrypoint = r.Kind, r.Entrypoint
		s.ProcStart, s.PIDDomain, s.PeerFeatures = r.ProcStart, r.PIDDomain, r.PeerFeatures
		s.StartedAt, s.UpdatedAt = r.StartedAt, r.UpdatedAt
		if s.SocketPath == "" {
			s.SocketPath = r.MessagingSocketPath
		}
	}

	out := make([]Session, 0, len(byPID))
	for _, s := range byPID {
		s.Live = Alive(s.PID, s.ProcStart)
		if s.SocketPath != "" {
			if k, err := ReadKey(s.PID, s.SocketPath); err == nil && k != nil {
				s.HasKey = true
			}
		}
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PID < out[j].PID })
	return out, nil
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
	// Reaching our OWN parent is not a peer connection, and should not be
	// made into one. The inherited child token identifies us as that
	// session's child, which skips cross-session handling entirely — no
	// permission-mode parity, no holding for approval, no exposure to a
	// session's refuse-cross-session-messages setting. The peer token from
	// the key file would work and would place us in exactly that machinery,
	// for a message from a process the session started itself.
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

// TargetFromEnv resolves the session that spawned this process, using
// CLAUDE_CODE_MESSAGING_SOCKET and the inherited child token.
func TargetFromEnv() (Target, bool) {
	path := os.Getenv(EnvMessagingSocket)
	if path == "" {
		return Target{}, false
	}
	t := Target{SocketPath: path, Token: os.Getenv(EnvMessagingToken)}
	if pid, ok := PIDFromSocketName(filepath.Base(path)); ok {
		t.PID = pid
	}
	return t, true
}
