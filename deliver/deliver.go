// Package deliver pushes a message into the harness that launched this
// process — and into nothing else.
//
// There is no address parameter anywhere here. The target comes from the
// process relationship: under Claude Code the socket and child token in the
// environment, under Codex the threadId on an inbound tool call. The package
// does not refuse to address other agents; it cannot.
//
// # The trailer
//
// Every delivered body ends with a bracketed trailer:
//
//	[cursor: <anchor>]                              re-fetchable
//	[no cursor: this message cannot be re-fetched]  not re-fetchable
//
// Either may end with " · more is waiting than this message carries". Its
// absence means the message was cut, so key on "ends with a bracketed
// trailer" and read it POSITIONALLY — a body may quote one.
//
// # Honesty about arrival
//
// A Receipt reports what was observed. Codex echoes the stored content, so it
// can be compared byte for byte; Claude Code acknowledges nothing, so the
// strongest truthful claim is that the bytes were written. A nil error means
// the call did what the Observation says, not "delivered".
package deliver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/secforge/harness-transport/udsmsg"
)

// Observation is what the backend actually observed about a delivery,
// ordered by strength.
type Observation int

const (
	// ObservedNothing: the bytes were written and accepted, and nothing
	// confirmed arrival. The most a Claude Code send can honestly report.
	ObservedNothing Observation = iota
	// ObservedAccepted means the server acknowledged taking the message.
	ObservedAccepted
	// ObservedStored: the server echoed the content and it matched byte for
	// byte, so the target holds exactly what was sent.
	ObservedStored
)

func (o Observation) String() string {
	switch o {
	case ObservedNothing:
		return "nothing"
	case ObservedAccepted:
		return "accepted"
	case ObservedStored:
		return "stored"
	}
	return fmt.Sprintf("observation(%d)", int(o))
}

// Delivery is one message to push. Cursor is the contract and Body the
// optimisation: a Body is expected to be re-fetchable from its Cursor, so
// nothing here assumes the push worked.
type Delivery struct {
	// Cursor is the anchor this message can be re-fetched from. Required.
	Cursor string
	Body   string
	// More reports that more is waiting than this delivery carries.
	More bool
}

// Receipt describes what happened, in terms the caller can act on and show a
// model verbatim.
type Receipt struct {
	// Observation is what was actually observed.
	Observation Observation
	// Detail is a sentence fit to show a model, stating plainly what is and
	// is not known.
	Detail string
}

// Deliverer pushes into the harness that launched this process.
type Deliverer interface {
	// Deliver pushes one message. A non-nil error means it certainly did not
	// arrive; nil with ObservedNothing means the write succeeded and arrival
	// is unverified.
	Deliver(ctx context.Context, d Delivery) (Receipt, error)
	// Available reports whether the harness can be reached, with a sentence
	// explaining a negative that can be shown to a model.
	Available() (bool, string)
	// MaxIntactBytes is a floor, not a ceiling: it assumes worst-case
	// encoding expansion, so it holds for content nobody inspected.
	MaxIntactBytes() (int, error)
	// Fits measures this exact delivery instead of the worst case — roughly
	// sixfold more room for prose.
	Fits(d Delivery) (ok bool, wireBytes int, err error)
	// Adopt latches the target from an inbound request's _meta. Safe on every
	// request: one carrying no thread id adopts nothing and reports no error,
	// and it is a no-op where the target came from the environment.
	Adopt(meta map[string]any) error
	Close() error
}

// Option configures a Deliverer.
type Option func(*options)

type options struct {
	senderName   string
	replyAddress string
	mode         udsmsg.Mode
}

// WithSenderName names this process in the delivered message. Identification,
// not authority: a name is composed by its sender.
//
// Without it the executable's name is used, which reads as "main" under
// `go run`.
func WithSenderName(name string) Option {
	return func(o *options) { o.senderName = name }
}

// WithReplyAddress makes deliveries repliable by naming an inbox of the
// caller's own, as udsmsg.Server.Addr returns; without it a delivery is
// one-way. The caller owns that inbox and who may write to it: an
// authenticated reply proves only that the sender could read the key file, so
// compare Peer.PID against the harness socket's pid for parent-only.
func WithReplyAddress(addr string) Option {
	return func(o *options) { o.replyAddress = addr }
}

// WithDetectedMode derives this process's permission posture from the session
// that spawned it; see udsmsg.DetectParentMode. When it cannot be
// established, nothing is asserted and the message may be held — the only
// guess that would help is the one that spends permission nobody gave.
func WithDetectedMode() Option {
	return func(o *options) {
		if m, err := udsmsg.DetectParentMode(); err == nil {
			o.mode = m
		}
	}
}

// Open returns a Deliverer for whichever harness launched this process. It
// never returns nil: with no harness reachable, the result says so through
// Available, which a caller can show a model.
func Open(opts ...Option) Deliverer {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	if o.senderName == "" {
		o.senderName = defaultSenderName()
	}
	if sock := os.Getenv(EnvClaudeSocket); sock != "" {
		return newClaude(sock, os.Getenv(EnvClaudeToken), o.senderName, o.replyAddress, o.mode)
	}
	// Deliberately no environment channel for Codex. An MCP server is handed
	// no thread, so one found in this environment came from something that
	// never chose this process — a stale export, a parent, another agent.
	// Latching it would deliver into someone else's thread and look like it
	// had worked. The target comes only from Adopt; until then the backend
	// reports itself unavailable, which fails closed.
	return newCodex(o.senderName)
}

// Environment a Claude Code harness session hands its children.
const (
	// EnvClaudeSocket holds the harness session's inbox path.
	EnvClaudeSocket = "CLAUDE_CODE_MESSAGING_SOCKET"
	// EnvClaudeToken holds the child token: a credential written to no file,
	// which only a process the session spawned can hold.
	EnvClaudeToken = "CLAUDE_CODE_MESSAGING_TOKEN"
)

// ClearEnvForTesting unsets every environment variable this package reads to
// find a harness, returning a function that restores them.
//
// A test binary inherits its harness's environment, so a suite exercising a
// delivery path without this fires its fixtures into a live conversation.
// That has happened. It lives here because the list to clear is the list this
// package reads, and a copy in a caller goes stale.
func ClearEnvForTesting() func() {
	saved := map[string]*string{}
	for _, k := range harnessEnv {
		if v, ok := os.LookupEnv(k); ok {
			v := v
			saved[k] = &v
		} else {
			saved[k] = nil
		}
		os.Unsetenv(k)
	}
	return func() {
		for k, v := range saved {
			if v == nil {
				os.Unsetenv(k)
				continue
			}
			os.Setenv(k, *v)
		}
	}
}

// harnessEnv is every variable Open consults. Adding a backend means adding
// its variables here, in the same package, next to the code that reads them.
var harnessEnv = []string{EnvClaudeSocket, EnvClaudeToken, EnvCodexSession}

// metaThreadID is the key the Codex harness stamps into each MCP request's _meta.
const metaThreadID = "threadId"

// Environment a Codex harness hands its shell-tool children. MCP servers do
// not get these — their thread arrives on tool-call metadata instead — but a
// hook or a spawned command does, so a child that is not an MCP server can be
// served without Adopt ever being called.
const (
	// EnvCodexSession holds the harness's root session id.
	EnvCodexSession = "CODEX_SESSION_ID"
)

// threadIDFromMeta extracts the harness's thread id from request metadata.
func threadIDFromMeta(meta map[string]any) (string, error) {
	if meta == nil {
		return "", errNoMeta
	}
	v, ok := meta[metaThreadID]
	if !ok {
		return "", errNoMeta
	}
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", fmt.Errorf("%s in request meta is %T, want a non-empty string", metaThreadID, v)
	}
	return s, nil
}

// errNoMeta reports metadata that carries no thread id. It is not a failure:
// a caller is expected to pass every request's meta, and most carry none.
var errNoMeta = fmt.Errorf("request meta carries no %s", metaThreadID)

// compose renders a delivery as the text the model sees. The cursor travels
// with it so a lost or cut Body still leaves an anchor to re-fetch from.
func compose(d Delivery) string {
	var b strings.Builder
	b.WriteString(d.Body)
	if b.Len() > 0 {
		b.WriteString("\n\n")
	}
	b.WriteString("[")
	switch {
	case d.Cursor != "":
		fmt.Fprintf(&b, "cursor: %s", d.Cursor)
	default:
		// A delivery with no anchor still gets a trailer, and says why it
		// has none. Callers use the trailer as an end marker — its absence
		// means the message was cut in transit — so a message that ended
		// without one would be indistinguishable from a truncated one.
		// That bites hardest on a client's own notices, which are the
		// messages most likely to carry no cursor and the ones a reader
		// can least afford to distrust.
		b.WriteString("no cursor: this message cannot be re-fetched")
	}
	if d.More {
		b.WriteString(" · more is waiting than this message carries")
	}
	b.WriteString("]")
	return b.String()
}

// unavailable is the Deliverer returned when no harness can be reached. Every
// call explains the same thing rather than failing obscurely.
type unavailable struct{ reason string }

func (u unavailable) Deliver(context.Context, Delivery) (Receipt, error) {
	return Receipt{}, fmt.Errorf("cannot deliver: %s", u.reason)
}
func (u unavailable) Available() (bool, string)    { return false, u.reason }
func (u unavailable) MaxIntactBytes() (int, error) { return 0, fmt.Errorf("%s", u.reason) }
func (u unavailable) Adopt(map[string]any) error   { return nil }
func (u unavailable) Close() error                 { return nil }
func (u unavailable) String() string               { return "unavailable: " + u.reason }
func (u unavailable) MarshalJSON() ([]byte, error) { return json.Marshal(u.reason) }
