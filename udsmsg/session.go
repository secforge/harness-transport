package udsmsg

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// PeerFeatures are the capabilities a session advertises in its registry
// entry. reply_across_default_dirs is what lets a peer accept a reply address
// outside the standard socket directories.
var PeerFeatures = []string{"notify_idle", "reply_across_default_dirs", "artifact_yield"}

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
	Name                string   `json:"name,omitempty"`
	NameSource          string   `json:"nameSource,omitempty"`
	NameSince           int64    `json:"nameSince,omitempty"`
	UpdatedAt           int64    `json:"updatedAt"`
	Status              string   `json:"status"`
}

// NewSessionEntry fills in a registry record for this process, describing the
// given inbox.
func NewSessionEntry(socketPath, name string) (*SessionEntry, error) {
	now := time.Now().UnixMilli()
	pid := os.Getpid()
	cwd, _ := os.Getwd()
	e := &SessionEntry{
		PID:                 pid,
		SessionID:           NewUUID(),
		CWD:                 cwd,
		StartedAt:           now,
		Version:             "2.1.272",
		PeerProtocol:        1,
		PeerFeatures:        PeerFeatures,
		Kind:                "interactive",
		Entrypoint:          "cli",
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
	if pd, err := PIDDomain(pid); err == nil {
		e.PIDDomain = pd
	}
	return e, nil
}

// NewMCPEntry builds a registry entry for an MCP server's own inbox.
//
// Registering is what lets the harness identify a reply target, and an
// unidentified target is what gets a reply held for approval. But an MCP
// server is not a session, so the entry must not read like one: the name
// carries BOTH the harness session it belongs to and the MCP server it is,
// and the kind says what it actually is rather than borrowing "interactive".
//
// harnessName is the parent session's own name — ParentSessionName reads it
// from the registry — and mcpName is the server's configured name, the one
// that appears as mcp:<name> in an attribution.
func NewMCPEntry(socketPath, harnessName, mcpName string) (*SessionEntry, error) {
	e, err := NewSessionEntry(socketPath, mcpEntryName(harnessName, mcpName))
	if err != nil {
		return nil, err
	}
	e.Kind = "mcp"
	e.Entrypoint = "mcp"
	return e, nil
}

// mcpEntryName composes the display name: the harness first, since that is
// the thing a reader is placing it against, then the server.
func mcpEntryName(harnessName, mcpName string) string {
	switch {
	case harnessName == "" && mcpName == "":
		return "mcp"
	case harnessName == "":
		return "mcp:" + mcpName
	case mcpName == "":
		return harnessName + " · mcp"
	}
	return harnessName + " · mcp:" + mcpName
}

// ParentSessionName returns the name of the session that spawned this
// process, read from its registry entry. Empty when there is no parent, no
// entry, or the entry carries no name — all of which are ordinary, so a
// caller should compose something usable rather than treating it as failure.
func ParentSessionName() string {
	sock := os.Getenv(EnvMessagingSocket)
	if sock == "" {
		return ""
	}
	pid, ok := PIDFromSocketName(filepath.Base(sock))
	if !ok {
		return ""
	}
	b, err := os.ReadFile(sessionEntryPath(pid))
	if err != nil {
		return ""
	}
	var e SessionEntry
	if err := json.Unmarshal(b, &e); err != nil {
		return ""
	}
	return e.Name
}

// sessionEntryPath is the registry file for a pid.
func sessionEntryPath(pid int) string {
	return filepath.Join(SessionsDir(), fmt.Sprintf("%d.json", pid))
}

// PublishSession writes a registry entry atomically, the way the key file is
// written, so a reader never sees a partial record.
func PublishSession(e *SessionEntry) error {
	if err := os.MkdirAll(SessionsDir(), 0o700); err != nil {
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

// NewUUID returns a random RFC 4122 version 4 UUID. Real sessions use this
// shape for both sessionId and msg_id, despite the 32-hex form the protocol
// notes describe.
func NewUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("udsmsg: crypto/rand failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}
