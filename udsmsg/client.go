package udsmsg

import (
	"context"
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
	if u.MsgID == "" {
		u.MsgID = NewMsgID()
	}
	if !MsgIDPattern.MatchString(u.MsgID) {
		return "", fmt.Errorf("msg_id %q is not a UUID; the receiver would not correlate it", u.MsgID)
	}
	if u.From != "" && !ValidAddress(u.From) {
		return "", fmt.Errorf("reply address %q is not well-shaped", u.From)
	}
	if u.Priority == "" {
		u.Priority = PriorityNext
	}
	content := u.Text
	if u.Attribution != nil {
		content = u.Attribution.Wrap(content)
	}
	f := &Frame{
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
	}
	if err := c.Send(f); err != nil {
		return "", err
	}
	return u.MsgID, nil
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
