package udsmsg

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// FirstLineTimeout is the receiver's deadline for a complete first line. A
// connection that dribbles bytes without completing a line inside this window
// is closed, so a client should build its payload before connecting.
const FirstLineTimeout = 30 * time.Second

// Client is a connection to one session's inbox.
type Client struct {
	conn   net.Conn
	target Target
}

// Dial connects to a resolved target and, if it has a token, presents the
// auth frame as the first line.
//
// A target whose published start time no longer matches the live process is
// refused before a byte is written: the pid has been recycled, and the socket
// now belongs to someone else.
func Dial(ctx context.Context, t Target) (*Client, error) {
	if t.PID != 0 && t.ProcStart != "" && !Alive(t.PID, t.ProcStart) {
		return nil, fmt.Errorf("pid %d is not the process that published %s", t.PID, t.SocketPath)
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", t.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", t.SocketPath, err)
	}
	c := &Client{conn: conn, target: t}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if t.Token != "" {
		if err := c.Send(&Frame{Type: TypeAuth, Token: t.Token}); err != nil {
			conn.Close()
			return nil, fmt.Errorf("send auth frame: %w", err)
		}
	}
	return c, nil
}

// DialPID resolves a session by pid and connects to it.
func DialPID(ctx context.Context, pid int) (*Client, error) {
	t, err := ResolveTarget(pid)
	if err != nil {
		return nil, err
	}
	return Dial(ctx, t)
}

// Target returns the destination this client is connected to.
func (c *Client) Target() Target { return c.target }

// Send writes one frame as a single line.
func (c *Client) Send(f *Frame) error {
	line, err := EncodeFrame(f)
	if err != nil {
		return err
	}
	if _, err := c.conn.Write(line); err != nil {
		return fmt.Errorf("write frame: %w", err)
	}
	return nil
}

// Close closes the connection. The receiver parses any trailing buffer before
// disconnecting, so a final line without a newline still arrives.
func (c *Client) Close() error { return c.conn.Close() }

// User describes a prompt to inject into a session's queue.
type User struct {
	// Text is the prompt. Empty text is ignored by the receiver.
	Text string
	// From is our reply address, "uds:<socket path>". Without it the receiver
	// has nowhere to send delivery status.
	From string
	// FromMode is our permission posture, used for permission-mode parity.
	FromMode Mode
	// MsgID correlates status replies. Generated if empty. It must be a
	// UUID: the receiver drops a non-UUID from its origin record, so every
	// later status arrives with no orig_msg_id to match, and a
	// notify_when_idle carrying one is discarded outright.
	MsgID string
	// UUID is the injected prompt's uuid. Optional and unvalidated; the
	// receiver generates one when it is absent.
	UUID string
	// SessionID, if set, must match the receiver's or the message is dropped.
	SessionID string
	// Attribution, when set, wraps Text so the peer sees a named message with
	// a reply address instead of an anonymous prompt.
	Attribution *CrossSession
	// Priority places the prompt in the receiver's queue. Defaults to
	// PriorityNext, what a session sends.
	Priority    string
	Attachments []Attachment
}

// SendUser injects a prompt and returns the message id it was sent under.
//
// This is fire-and-forget: the receiver queues the prompt and answers in its
// own transcript, not on this connection. Delivery status and any reply
// arrive at the From address, which requires an inbox of your own.
func (c *Client) SendUser(u User) (msgID string, err error) {
	f, err := BuildUserFrame(&u)
	if err != nil {
		return "", err
	}
	if err := c.Send(f); err != nil {
		return "", err
	}
	return u.MsgID, nil
}

// BuildUserFrame renders a User as the frame that would be sent, filling in
// the fields SendUser fills in. It is exported so a caller can measure what a
// send would cost without sending it — see EncodedUserSize — with no second
// construction that could drift from this one.
//
// It takes a pointer because it completes the User in place: a caller that
// measures and then sends reuses the same generated msg_id rather than
// getting a different one on each call.
func BuildUserFrame(u *User) (*Frame, error) {
	if u.MsgID == "" {
		u.MsgID = NewMsgID()
	}
	if !MsgIDPattern.MatchString(u.MsgID) {
		return nil, fmt.Errorf("msg_id %q is not a UUID; the receiver would not correlate it", u.MsgID)
	}
	if u.From != "" && !ValidAddress(u.From) {
		return nil, fmt.Errorf("reply address %q is not well-shaped", u.From)
	}
	if u.Priority == "" {
		u.Priority = PriorityNext
	}
	content := u.Text
	if u.Attribution != nil {
		content = u.Attribution.Wrap(content)
	}
	return &Frame{
		MsgV:            MsgVersion,
		Type:            TypeUser,
		MsgID:           u.MsgID,
		From:            u.From,
		FromMode:        u.FromMode,
		Priority:        u.Priority,
		SessionID:       u.SessionID,
		Message:         &UserMessage{Role: "user", Content: content},
		FileAttachments: u.Attachments,
		UUID:            u.UUID,
	}, nil
}

// EncodedUserSize reports how many bytes the frame for u would occupy on the
// wire, newline included, and whether that is within the receiver's line cap.
//
// A line over the cap costs the whole connection rather than just the
// message, so a caller holding a large body should ask this rather than
// reason about escaping: JSON inflates "<", ">", "&" and control characters
// six-fold, which no rule of thumb about quotes and newlines predicts.
func EncodedUserSize(u User) (size int, fits bool, err error) {
	f, err := BuildUserFrame(&u)
	if err != nil {
		return 0, false, err
	}
	b, err := json.Marshal(f)
	if err != nil {
		return 0, false, fmt.Errorf("marshal frame: %w", err)
	}
	size = len(b) + 1 // the newline EncodeFrame appends
	return size, size <= MaxLineBytes, nil
}

// SendControl writes a control frame, filling in the type.
func (c *Client) SendControl(f *Frame) error {
	f.Type = TypeControl
	if f.Action == "" {
		return fmt.Errorf("control frame needs an action")
	}
	return c.Send(f)
}

// Rename renames the receiving session.
func (c *Client) Rename(name string) error {
	if name == "" {
		return fmt.Errorf("rename needs a name")
	}
	return c.SendControl(&Frame{Action: ActionRename, Name: name})
}

// NotifyWhenIdle subscribes to the receiver's next idle moment. The
// subscription is dropped by the receiver if from is unshaped, outside the
// socket namespace, or resolves to the sender itself.
func (c *Client) NotifyWhenIdle(from, msgID string, mode Mode) error {
	if _, err := ResolveReplyAddr(from); err != nil {
		return fmt.Errorf("notify_when_idle reply address: %w", err)
	}
	if msgID == "" {
		return fmt.Errorf("notify_when_idle needs a msg_id")
	}
	return c.SendControl(&Frame{Action: ActionNotifyWhenIdle, From: from, MsgID: msgID, FromMode: mode})
}

// SendPeerMessageStatus reports delivery feedback for an earlier send.
func (c *Client) SendPeerMessageStatus(f *Frame) error {
	f.Action = ActionPeerMessageStatus
	return c.SendControl(f)
}
