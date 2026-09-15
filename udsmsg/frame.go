// Package udsmsg implements the Claude Code session-to-session messaging
// protocol (`uds-messaging`): newline-delimited JSON frames over a unix
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
	TypeAuth    = "auth"
	TypeUser    = "user"
	TypeControl = "control"
)

// Control actions dispatched by a session.
const (
	ActionRename                 = "rename"
	ActionPeerMessageStatus      = "peer_message_status"
	ActionNotifyWhenIdle         = "notify_when_idle"
	ActionPeerIdleNotice         = "peer_idle_notice"
	ActionYieldArtifactReplies   = "yield_artifact_replies"
	ActionUnyieldArtifactReplies = "unyield_artifact_replies"
	ActionArtifactRepliesYielded = "artifact_replies_yielded"
)

// Statuses carried by a peer_message_status frame.
const (
	StatusHeld      = "held"
	StatusDenied    = "denied"
	StatusExpired   = "expired"
	StatusDelivered = "delivered"
	StatusRefused   = "refused"
	StatusDropped   = "dropped"
)

// Mode is a sender's permission posture, used by the receiver for
// permission-mode parity. A "bypass" sender's message may be held.
type Mode string

const (
	ModePrompting Mode = "prompting"
	ModeBypass    Mode = "bypass"
)

// Attachment is one element of a user frame's file_attachments.
type Attachment struct {
	FileUUID string `json:"file_uuid"`
	FileName string `json:"file_name"`
	IsImage  bool   `json:"is_image,omitempty"`
	SHA256   string `json:"sha256,omitempty"`
	FileSize int64  `json:"file_size,omitempty"`
}

// UserMessage is the prompt payload of a user frame.
type UserMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Requester is the optional origin record on a yield_artifact_replies frame.
type Requester struct {
	CWD  string `json:"cwd,omitempty"`
	Tmux string `json:"tmux,omitempty"`
}

// Frame is one protocol line. It is a union over every frame kind: only the
// fields relevant to Type and Action are populated. Unknown fields survive a
// round trip in Raw, which holds the line exactly as received.
type Frame struct {
	MsgV      int    `json:"msgV,omitempty"`
	Type      string `json:"type"`
	SessionID string `json:"session_id,omitempty"`
	MsgID     string `json:"msg_id,omitempty"`
	From      string `json:"from,omitempty"`
	FromMode  Mode   `json:"from_mode,omitempty"`
	Priority  string `json:"priority,omitempty"`

	// type=auth
	Token string `json:"token,omitempty"`

	// type=user
	Message         *UserMessage `json:"message,omitempty"`
	FileAttachments []Attachment `json:"file_attachments,omitempty"`
	// UUID becomes the injected prompt's uuid. Unlike MsgID it is not
	// validated and is no use as a correlation handle; omitted, the receiver
	// generates one.
	UUID string `json:"uuid,omitempty"`

	// type=control
	Action string `json:"action,omitempty"`

	// action=rename
	Name string `json:"name,omitempty"`

	// action=peer_message_status
	Status        string   `json:"status,omitempty"`
	StatusDetail  string   `json:"status_detail,omitempty"`
	Reason        string   `json:"reason,omitempty"`
	OrigMsgID     string   `json:"orig_msg_id,omitempty"`
	DropReason    string   `json:"drop_reason,omitempty"`
	DroppedMsgIDs []string `json:"dropped_msg_ids,omitempty"`

	// action=peer_idle_notice
	State      string   `json:"state,omitempty"`
	FinishedAt *float64 `json:"finished_at,omitempty"`
	Detail     string   `json:"detail,omitempty"`

	// action=yield_artifact_replies / unyield / yielded
	Slugs     []string        `json:"slugs,omitempty"`
	SentAt    *float64        `json:"sent_at,omitempty"`
	ClaimedAt *float64        `json:"claimed_at,omitempty"`
	Requester *Requester      `json:"requester,omitempty"`
	Stopped   *bool           `json:"stopped,omitempty"`
	Yielded   json.RawMessage `json:"yielded,omitempty"`
	NotHeld   json.RawMessage `json:"not_held,omitempty"`
	Refused   json.RawMessage `json:"refused,omitempty"`

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
