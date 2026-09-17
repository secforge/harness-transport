// Package udsmsg implements the observed Claude Code session-to-session
// messaging protocol, called `uds-messaging` here: newline-delimited JSON frames over a Unix
// domain socket, one socket per session.
//
// The protocol is undocumented by Anthropic and can change in any release.
// See docs/claude-uds-messaging.adoc for the observed reference
// this package targets (Claude Code 2.1.272).
package udsmsg

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// MaxLineBytes is the documented per-line cap: a longer line closes the
// connection, rather than dropping that line alone.
const MaxLineBytes = 1 << 20

// Frame types.
const (
	TypeAuth = "auth"
	TypeUser = "user"
)

// Mode is a sender's permission posture, carried as from_mode. Sessions
// observed here send exactly one value, and it is the only one this package
// will put on the wire: a posture it cannot attest is not asserted at all.
type Mode string

const ModePrompting Mode = "prompting"

// UserMessage is the prompt payload of a user frame.
type UserMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Frame is one protocol line. Only the fields relevant to Type are
// populated. Unknown fields survive a
// round trip in Raw, which holds the line exactly as received.
type Frame struct {
	MsgV     int    `json:"msgV,omitempty"`
	Type     string `json:"type"`
	MsgID    string `json:"msg_id,omitempty"`
	From     string `json:"from,omitempty"`
	FromMode Mode   `json:"from_mode,omitempty"`
	Priority string `json:"priority,omitempty"`

	// type=auth
	Token string `json:"token,omitempty"`

	// type=user
	Message *UserMessage `json:"message,omitempty"`

	// Raw is the undecoded line. Set on receive, ignored on send.
	Raw json.RawMessage `json:"-"`
}

// IsAuth reports whether the frame is an auth frame. The receiver's guard is
// loose about shape and strict about the token: extra fields are tolerated.
func (f *Frame) IsAuth() bool { return f.Type == TypeAuth }

// Text returns the prompt text of a user frame, or "" when the frame carries
// no message.
func (f *Frame) Text() string {
	if f.Message == nil {
		return ""
	}
	return f.Message.Content
}

// decodeFrame parses one line. Raw is set to a copy of the input.
func decodeFrame(line []byte) (*Frame, error) {
	var f Frame
	if err := json.Unmarshal(line, &f); err != nil {
		return nil, fmt.Errorf("parse JSON line: %w", err)
	}
	f.Raw = append(json.RawMessage(nil), line...)
	return &f, nil
}

// encodeFrame marshals a frame as a newline-terminated line, rejecting one
// over the documented line cap — a longer line closes the connection.
func encodeFrame(f *Frame) ([]byte, error) {
	b, err := json.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("marshal frame: %w", err)
	}
	if len(b)+1 > MaxLineBytes {
		return nil, fmt.Errorf("frame is %d bytes, over the %d byte line cap", len(b)+1, MaxLineBytes)
	}
	return append(b, '\n'), nil
}

// msgIDPattern is the RFC-4122 shape sessions were observed to send as a
// msg_id. The 32-hex form that appears elsewhere in this protocol is a Windows
// pipe name, not a message id.
var msgIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// newMsgID returns a sender-assigned message id, the UUID shape Claude Code
// itself sends and validates.
func newMsgID() string { return newUUID() }
