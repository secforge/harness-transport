// Package udsmsg implements the observed Claude Code session-to-session
// messaging protocol, called `uds-messaging` here: newline-delimited JSON frames over a Unix
// domain socket, one socket per session.
//
// The protocol is undocumented by Anthropic and can change in any release.
// See docs/claude-uds-messaging.adoc for the observed reference
// this package targets (Claude Code 2.1.272).
package udsmsg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
)

// MaxLineBytes is the per-line cap the receiver enforces. A longer line drops
// the whole connection, not just that line.
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
	// UUID becomes the injected prompt's uuid. Unlike MsgID it is not
	// validated and is no use as a correlation handle; omitted, the receiver
	// generates one.
	UUID string `json:"uuid,omitempty"`

	// Raw is the undecoded line. Set on receive, ignored on send.
	Raw json.RawMessage `json:"-"`
}

// IsAuth reports whether the frame is an auth frame. The receiver's guard is
// loose about shape and strict about the token: extra fields are tolerated.
func (f *Frame) IsAuth() bool { return f.Type == TypeAuth }

// Text returns the prompt text of a user frame. Missing or empty content
// yields "", which the receiver ignores.
func (f *Frame) Text() string {
	if f.Message == nil {
		return ""
	}
	return f.Message.Content
}

// DecodeFrame parses one line. Raw is set to a copy of the input.
func DecodeFrame(line []byte) (*Frame, error) {
	var f Frame
	if err := json.Unmarshal(line, &f); err != nil {
		return nil, fmt.Errorf("parse JSON line: %w", err)
	}
	f.Raw = append(json.RawMessage(nil), line...)
	return &f, nil
}

// EncodeFrame marshals a frame as a newline-terminated line, rejecting one
// that would exceed the receiver's cap.
func EncodeFrame(f *Frame) ([]byte, error) {
	b, err := json.Marshal(f)
	if err != nil {
		return nil, fmt.Errorf("marshal frame: %w", err)
	}
	if len(b)+1 > MaxLineBytes {
		return nil, fmt.Errorf("frame is %d bytes, over the %d byte line cap", len(b)+1, MaxLineBytes)
	}
	return append(b, '\n'), nil
}

// MsgIDPattern is the receiver's validator for a message id. A frame whose
// msg_id fails it cannot be correlated, so status and idle notices for it go
// unmatched — silently, since nothing rejects the message itself.
//
// The 32-hex form that appears elsewhere in this protocol is the Windows
// named-pipe name, not a message id.
var MsgIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// NewMsgID returns a sender-assigned message id, the UUID shape Claude Code
// itself sends and validates.
func NewMsgID() string { return NewUUID() }

// splitLines splits a buffer on '\n', returning the complete lines and the
// remaining partial tail.
func splitLines(buf []byte) (lines [][]byte, rest []byte) {
	for {
		i := bytes.IndexByte(buf, '\n')
		if i < 0 {
			return lines, buf
		}
		lines = append(lines, buf[:i])
		buf = buf[i+1:]
	}
}
