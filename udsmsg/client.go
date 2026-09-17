package udsmsg

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// FirstLineTimeout is the documented deadline for a complete first line. A
// connection that dribbles bytes without completing a line inside this window
// is closed, so a client should build its payload before connecting.
const FirstLineTimeout = 30 * time.Second

// Client is a connection to one session's inbox.
type Client struct {
	conn   net.Conn
	target Target
}

// Dial connects to a resolved target, presenting the auth frame first when it
// has a token. A target whose start time no longer matches the live process is
// refused before a byte is written: the pid has been recycled.
//
// DIALLING WITHOUT A TOKEN IS NOT PORTABLE. An inbox that requires one closes
// with no error and no reason, and authentication is optional on Linux and
// macOS but on by default on Windows — so tokenless code works in development
// and dies silently where it is hardest to debug. Dial refuses unless
// Target.Unauthenticated says otherwise.
func Dial(ctx context.Context, t Target) (*Client, error) {
	if t.PID != 0 && t.ProcStart != "" && !Alive(t.PID, t.ProcStart) {
		return nil, fmt.Errorf("pid %d is not the process that published %s", t.PID, t.SocketPath)
	}
	if t.Token == "" && !t.Unauthenticated {
		return nil, fmt.Errorf("refusing to dial %s without a token: a receiver that requires "+
			"authentication drops every line and destroys the connection without sending a reason, "+
			"which is the default on Windows — so this would work here and fail invisibly there. "+
			"Use the inherited child token for our own parent, the published peer token for any "+
			"other session, or set Target.Unauthenticated to say the risk is intended",
			t.SocketPath)
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

// Target returns the destination this client is connected to.
func (c *Client) Target() Target { return c.target }

// Send writes one frame as a single line.
func (c *Client) Send(f *Frame) error {
	line, err := encodeFrame(f)
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
	// Text is the prompt.
	Text string
	// From is our reply address, "uds:<socket path>". Without it a recipient
	// has nowhere to answer.
	From string
	// FromMode is our permission posture, used for permission-mode parity.
	FromMode Mode
	// MsgID identifies the message. Generated if empty, and required to be a
	// UUID because that is the shape sessions were observed to send.
	MsgID string
	// Attribution, when set, wraps Text so the peer sees a named message with
	// a reply address instead of an anonymous prompt.
	Attribution *CrossSession
	// Priority is sent as given, defaulting to priorityNext — the value
	// sessions were observed to send.
	Priority string
}

// SendUser injects a prompt and returns the message id it was sent under.
//
// This is fire-and-forget: nothing comes back on this connection. Anything a
// recipient chooses to send arrives at the From address, which means having an
// inbox of your own.
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

// BuildUserFrame renders a User as the frame SendUser would send, so a caller
// can measure one without sending it (see EncodedUserSize) and the two cannot
// drift. It completes the User in place, so measuring then sending reuses the
// same generated msg_id.
func BuildUserFrame(u *User) (*Frame, error) {
	if u.MsgID == "" {
		u.MsgID = newMsgID()
	}
	if !msgIDPattern.MatchString(u.MsgID) {
		return nil, fmt.Errorf("msg_id %q is not the UUID shape this protocol uses", u.MsgID)
	}
	if u.From != "" && !validAddress(u.From) {
		return nil, fmt.Errorf("reply address %q is not well-shaped", u.From)
	}
	if u.Priority == "" {
		u.Priority = priorityNext
	}
	content := u.Text
	if u.Attribution != nil {
		content = u.Attribution.Wrap(content)
	}
	return &Frame{
		MsgV:     msgVersion,
		Type:     TypeUser,
		MsgID:    u.MsgID,
		From:     u.From,
		FromMode: u.FromMode,
		Priority: u.Priority,
		Message:  &UserMessage{Role: "user", Content: content},
	}, nil
}

// EncodedUserSize reports the frame's size on the wire, newline included, and
// whether it fits the line cap. Worth asking rather than estimating: an
// oversize line costs the connection, and JSON inflates "<", ">" and "&"
// sixfold.
func EncodedUserSize(u User) (size int, fits bool, err error) {
	f, err := BuildUserFrame(&u)
	if err != nil {
		return 0, false, err
	}
	b, err := json.Marshal(f)
	if err != nil {
		return 0, false, fmt.Errorf("marshal frame: %w", err)
	}
	size = len(b) + 1 // the newline encodeFrame appends
	return size, size <= MaxLineBytes, nil
}
