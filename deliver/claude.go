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
	// replyTo is an inbox of the caller's own, named in the envelope so the
	// model can answer with its ordinary reply rather than another tool.
	// Empty means one-way, which is the default.
	replyTo string
	// mode is this process's asserted permission posture, or empty for no
	// claim — the honest value when the posture cannot be established, and
	// the one that risks a hold rather than a false statement.
	mode udsmsg.Mode

	mu   sync.Mutex
	name string
}

func newClaude(socket, token, name, replyTo string, mode udsmsg.Mode) Deliverer {
	if name == "" {
		name = defaultSenderName()
	}
	return &claudeBackend{socket: socket, token: token, name: name, replyTo: replyTo, mode: mode}
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

// worstCaseEscape is how much JSON encoding can inflate a body, measured
// rather than assumed (encoding/json, 2026-09-15, 1000-byte samples):
//
//	a           x1    "  \  \n   x2    <  >  &  0x01   x6
//
// The x6 cases are the ones that matter and the ones easy to miss: Go
// escapes <, > and & to \u003c-style sequences by default, so HTML, XML,
// code, or a quoted protocol envelope inflates six-fold where prose does not
// inflate at all. An earlier version of this file reserved a factor of two,
// which was true of quotes and newlines and false of every angle bracket.
const worstCaseEscape = 6

// MaxIntactBytes returns a floor rather than the true ceiling.
//
// The receiver caps a line at 1 MiB and drops the whole CONNECTION over it,
// not merely the message, so this number has to hold for content the caller
// has not looked at. It is therefore the cap divided by the worst-case
// escape expansion — see worstCaseEscape — and not by the factor of two that
// quotes and newlines would suggest.
//
// The result is far below what ordinary text achieves: a 1,000,019-byte
// payload of prose enveloped to 1,014,898 bytes and arrived whole, because
// barely 1.4% of it needed escaping. That is what DemonstratedIntactBytes
// records. This one answers a different question — "what may I send without
// having inspected it" — and a caller sizing a split wants this one. A caller
// that has the body in hand can ask Fits instead and use the real ceiling.
func (c *claudeBackend) MaxIntactBytes() (int, error) {
	return (udsmsg.MaxLineBytes - claudeOverhead) / worstCaseEscape, nil
}

// Fits measures the delivery as the frame that would actually be sent,
// sharing its construction with the send path so the two cannot disagree.
func (c *claudeBackend) Fits(d Delivery) (bool, int, error) {
	c.mu.Lock()
	name := c.name
	c.mu.Unlock()
	size, fits, err := udsmsg.EncodedUserSize(udsmsg.User{
		Text:        compose(d),
		From:        c.replyTo,
		Attribution: &udsmsg.CrossSession{From: c.replyTo, Name: name, Mode: c.mode},
	})
	return fits, size, err
}

func (c *claudeBackend) Available() (bool, string) {
	if c.socket == "" {
		return false, "this process was not launched by a Claude Code harness, so there is no session to deliver into"
	}
	if fi, err := os.Stat(c.socket); err != nil || fi.Mode()&os.ModeSocket == 0 {
		return false, fmt.Sprintf("the harness session's inbox at %s is gone, so the harness that launched this process is no longer listening", c.socket)
	}
	if c.token == "" {
		// Not a warning. A receiver that requires authentication destroys an
		// unauthenticated connection and sends no reason, which is the
		// default on Windows — so delivering without the inherited token
		// would work here and fail invisibly elsewhere. Every process a
		// session spawns is given the token, so its absence means this
		// process was not spawned by the session it is pointed at.
		return false, "the harness session's inbox is there, but no child token was inherited — " +
			"this process was not started by that session, and delivering without the token would " +
			"be refused without explanation on a harness that requires it"
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

	// The address is carried twice on purpose: on the frame, where the
	// harness sends delivery status, and inside the envelope, which is what
	// the model sees and replies to. Empty in both places leaves the
	// delivery one-way, as it is by default.
	msgID, err := client.SendUser(udsmsg.User{
		Text: text,
		From: c.replyTo,
		// The mode goes on the FRAME, where the receiver's accept-or-hold
		// decision reads it, and in the envelope, where it is displayed.
		// Asserting one in only one place would be incoherent, and the
		// frame is the one that decides.
		FromMode: c.mode,
		Attribution: &udsmsg.CrossSession{
			From: c.replyTo,
			Name: name,
			Mode: c.mode,
		},
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
