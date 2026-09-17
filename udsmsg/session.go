package udsmsg

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
)

// peerFeatures are the capability strings a session was observed to advertise
// in its registry entry. They are reproduced so an entry looks like the ones
// alongside it; what a reader does with them is not observable from here.
var peerFeatures = []string{"notify_idle", "reply_across_default_dirs", "artifact_yield"}

// SessionEntry is a registry record, ~/.claude/sessions/<pid>.json. Publishing
// one makes a process discoverable as a session: other sessions list it, and a
// receiver can attribute messages from it by name.
type SessionEntry struct {
	PID                 int      `json:"pid"`
	SessionID           string   `json:"sessionId"`
	CWD                 string   `json:"cwd"`
	StartedAt           int64    `json:"startedAt"`
	ProcStart           string   `json:"procStart"`
	Version             string   `json:"version"`
	PeerProtocol        int      `json:"peerProtocol"`
	PeerFeatures        []string `json:"peerFeatures"`
	Kind                string   `json:"kind"`
	Entrypoint          string   `json:"entrypoint"`
	PIDDomain           string   `json:"pidDomain"`
	MessagingSocketPath string   `json:"messagingSocketPath"`
	// Name is what a reader of the registry displays for this process. It is
	// the caller's, and NewSessionEntry takes it as given apart from
	// refusing the values that would corrupt a display: empty, or carrying a
	// control character. No length is enforced — none was observed.
	//
	// It confers nothing. Any process of the same uid can publish an entry
	// under any name, so a name is a label, never evidence.
	Name       string `json:"name,omitempty"`
	NameSource string `json:"nameSource,omitempty"`
	NameSince  int64  `json:"nameSince,omitempty"`
	UpdatedAt  int64  `json:"updatedAt"`
	Status     string `json:"status"`
}

// NewSessionEntry fills in a registry record for this process. Kind and
// entrypoint come from the caller and are not defaulted: only the caller knows
// what this process is, and an entry saying "interactive" when it is not is
// read as a session by everything that lists the registry.
//
// The name is rejected rather than repaired when it cannot be displayed — see
// Name — because a caller that passed something unusable should hear so, not
// discover later that it publishes under something it did not choose.
func NewSessionEntry(socketPath, name, kind, entrypoint string) (*SessionEntry, error) {
	if err := checkEntryName(name); err != nil {
		return nil, err
	}
	now := time.Now().UnixMilli()
	pid := os.Getpid()
	cwd, _ := os.Getwd()
	e := &SessionEntry{
		PID:                 pid,
		SessionID:           newUUID(),
		CWD:                 cwd,
		StartedAt:           now,
		Version:             "2.1.272",
		PeerProtocol:        1,
		PeerFeatures:        peerFeatures,
		Kind:                kind,
		Entrypoint:          entrypoint,
		MessagingSocketPath: socketPath,
		Name:                name,
		NameSource:          "user",
		NameSince:           now,
		UpdatedAt:           now,
		Status:              "idle",
	}
	ps, err := ProcStart(pid)
	if err != nil {
		return nil, err
	}
	e.ProcStart = ps
	if pd, err := pidDomain(pid); err == nil {
		e.PIDDomain = pd
	}
	return e, nil
}

// checkEntryName refuses a name a reader could not display as given.
func checkEntryName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("a registry entry needs a name")
	}
	for _, r := range name {
		if unicode.Is(unicode.Cc, r) {
			return fmt.Errorf("name %q contains a control character", name)
		}
	}
	return nil
}

// sessionEntryPath is the registry file for a pid.
func sessionEntryPath(pid int) string {
	return filepath.Join(sessionsDir(), fmt.Sprintf("%d.json", pid))
}

// PublishSession writes a registry entry atomically, the way the key file is
// written, so a reader never sees a partial record.
func PublishSession(e *SessionEntry) error {
	if err := os.MkdirAll(sessionsDir(), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	final := sessionEntryPath(e.PID)
	tmp := fmt.Sprintf("%s.tmp.%s", final, hex.EncodeToString(suffix[:]))
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// UnpublishSession removes this process's registry entry.
func UnpublishSession(pid int) error {
	if err := os.Remove(sessionEntryPath(pid)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// newUUID returns a random RFC 4122 version 4 UUID. Real sessions use this
// shape for both sessionId and msg_id, despite the 32-hex form the protocol
// notes describe.
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("udsmsg: crypto/rand failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}
