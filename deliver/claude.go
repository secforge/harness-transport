package deliver

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/secforge/harness-transport/udsmsg"
)

// claudeBackend delivers into the Claude Code harness session that spawned us.
//
// It addresses the socket named in our own environment and authenticates with
// the child token from the same place. It never reads the session registry or
// a key file, so it cannot discover, name or reach any other session.
type claudeBackend struct {
	socket string
	token  string

	mu   sync.Mutex
	name string
}

func newClaude(socket, token, name string) Deliverer {
	if name == "" {
		name = defaultSenderName()
	}
	return &claudeBackend{socket: socket, token: token, name: name}
}

// defaultSenderName identifies this process in the delivered message. It is
// attribution, not authority: the receiver takes identity from the socket
// credentials and ignores what a sender claims.
func defaultSenderName() string {
	if exe, err := os.Executable(); err == nil {
		return filepath.Base(exe)
	}
	return "mcp"
}

// claudeOverhead is reserved out of the line cap for the JSON envelope, the
// attribution wrapper and the cursor trailer.
const claudeOverhead = 8 << 10

// MaxIntactBytes returns a floor rather than the true ceiling.
//
// The receiver caps a line at 1 MiB and drops the whole connection over it,
// and the body is JSON-escaped on the way, which can double the size of text
// that is all quotes and newlines. Halving the budget makes the number one a
// caller can rely on for ANY content, rather than one that holds until someone
// sends a transcript full of escapes.
//
// It is therefore lower than DemonstratedIntactBytes, which is measured on
// ordinary text: a 1,000,019-byte payload of that shape enveloped to 1,014,898
// bytes, comfortably inside the cap, because barely 1.4% of it needed
// escaping. The same byte count of quote-dense content would not fit. The
// enforced figure answers "what may I always send", the measured one answers
// "what has been seen to arrive" — and a caller splitting messages wants the
// first.
func (c *claudeBackend) MaxIntactBytes() (int, error) {
	return (udsmsg.MaxLineBytes - claudeOverhead) / 2, nil
}

func (c *claudeBackend) Available() (bool, string) {
	if c.socket == "" {
		return false, "this process was not launched by a Claude Code harness, so there is no session to deliver into"
	}
	if fi, err := os.Stat(c.socket); err != nil || fi.Mode()&os.ModeSocket == 0 {
		return false, fmt.Sprintf("the harness session's inbox at %s is gone, so the harness that launched this process is no longer listening", c.socket)
	}
	if c.token == "" {
		// Auth is optional on the receiving side, so this is a warning
		// rather than a refusal.
		return true, "the harness session is reachable, but no child token was inherited, so the delivery will be unauthenticated"
	}
	return true, "the Claude Code harness that launched this process is reachable"
}

// Adopt is a no-op: the target came from the environment at exec and cannot
// be changed by anything a caller passes.
func (c *claudeBackend) Adopt(map[string]any) error { return nil }

func (c *claudeBackend) Close() error { return nil }

func (c *claudeBackend) Deliver(ctx context.Context, d Delivery) (Receipt, error) {
	if ok, reason := c.Available(); !ok {
		return Receipt{}, fmt.Errorf("cannot deliver: %s", reason)
	}
	text := compose(d)
	if max, _ := c.MaxIntactBytes(); len(text) > max {
		// Refuse rather than cut: an oversize line costs the whole
		// connection, and a silently shortened message is the failure this
		// package exists to avoid.
		return Receipt{SentBytes: len(text)}, fmt.Errorf(
			"message is %d bytes, over the %d the harness session will accept intact; "+
				"deliver a shorter body and leave the rest to be fetched from the cursor",
			len(text), max)
	}

	c.mu.Lock()
	name := c.name
	c.mu.Unlock()

	target := udsmsg.Target{SocketPath: c.socket, Token: c.token}
	if pid, ok := udsmsg.PIDFromSocketName(filepath.Base(c.socket)); ok {
		target.PID = pid
		// Bind the delivery to the process that published this socket: a
		// recycled pid is a different session, and delivering to it would be
		// the cross-session injection this package exists to prevent.
		if ps, err := udsmsg.ProcStart(pid); err == nil {
			target.ProcStart = ps
		}
	}

	client, err := udsmsg.Dial(ctx, target)
	if err != nil {
		return Receipt{SentBytes: len(text)}, fmt.Errorf("the harness session did not accept a connection: %w", err)
	}
	defer client.Close()

	msgID, err := client.SendUser(udsmsg.User{
		Text: text,
		// No reply address: this is a push into our own harness, and there is
		// nothing here to answer to.
		Attribution: &udsmsg.CrossSession{Name: name, Mode: udsmsg.ModePrompting},
	})
	if err != nil {
		return Receipt{SentBytes: len(text)}, fmt.Errorf("the message was not written to the harness session: %w", err)
	}

	return Receipt{
		Observation: ObservedNothing,
		Detail: "Written to the Claude Code harness session's inbox, which accepted the connection and the bytes. " +
			"This transport sends no receipt for a message it accepts, so arrival in the session's context is unverified — " +
			"treat the message as probably sent, not as read.",
		SentBytes: len(text),
		Ref:       msgID,
	}, nil
}
