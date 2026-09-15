// Package deliver pushes a message into the harness that launched this
// process — and into nothing else.
//
// An MCP server's authority is derived entirely from the session that spawned
// it: it runs as that session's child, inside that user's permission
// decisions. A library that could address any reachable agent would let any
// MCP server inject text into any other session, bypassing that session's own
// user. For a caller relaying untrusted content — from a chat server, from
// people who are not the operator — that would hand the content a channel it
// must not have.
//
// So there is no address parameter anywhere in this package. The target is
// derived from the process relationship:
//
//   - Under Claude Code, from the environment a harness session hands its
//     children: CLAUDE_CODE_MESSAGING_SOCKET is that session's inbox and
//     CLAUDE_CODE_MESSAGING_TOKEN is the child token — a credential written to
//     no file, held only by processes the session spawned. The peer token, by
//     contrast, sits in a key file any process of the same uid can read; that
//     one is an address book, and this package never touches it.
//   - Under Codex, from the tool call: the harness stamps "threadId" into each
//     MCP request's _meta, so Adopt latches the target from what arrived
//     rather than from anything a caller composed.
//
// The library therefore does not refuse to address other agents. It has
// nothing with which to address them.
//
// # The trailer
//
// Every delivered body ends with a bracketed trailer, and callers rely on
// that: its absence means the message was cut in transit, so a reader may
// treat an unterminated delivery as incomplete and decline to act on it.
//
// There are two forms, and a caller keying on the first alone will misread
// the second as a missing marker:
//
//	[cursor: <anchor>]                              re-fetchable from the anchor
//	[no cursor: this message cannot be re-fetched]  no anchor — typically a
//	                                                notice the client wrote
//	                                                itself rather than relayed
//
// A pending remainder appends " · more is waiting than this message carries"
// to either form. So the rule to key on is "ends with a bracketed trailer",
// not "ends with a cursor line".
//
// # Honesty about arrival
//
// Deliver reports what was observed, never what is hoped. The two backends
// differ sharply and the difference is reported rather than smoothed over:
// Codex returns an application-level receipt that echoes the stored content,
// which can be compared byte for byte; Claude Code issues no receipt at all
// for an ordinary accepted message, so the strongest truthful claim is that
// the bytes were written and the socket took them. A nil error means "the call
// did what the Observation says", not "delivered".
package deliver

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Observation is what the backend actually observed about a delivery. The
// values are ordered by strength, but a caller should switch on them rather
// than compare them: ObservedTurnRan is evidence of a different kind, not a
// stronger ObservedAccepted.
type Observation int

const (
	// ObservedNothing means the bytes were written and the transport
	// accepted them. Nothing confirmed arrival. This is the most a Claude
	// Code session can honestly report for an accepted message.
	ObservedNothing Observation = iota
	// ObservedTurnRan means the target ran a turn after the delivery. It
	// correlates with the message having been read and is not evidence of
	// it — the session may have run for any reason, a user typing included.
	// Never treat it as a read.
	ObservedTurnRan
	// ObservedAccepted means the server acknowledged taking the message.
	ObservedAccepted
	// ObservedStored means the server echoed the content back and it matched
	// byte for byte, so the target holds exactly what was sent.
	ObservedStored
	// ObservedConsumed means the target produced output for this message.
	ObservedConsumed
)

func (o Observation) String() string {
	switch o {
	case ObservedNothing:
		return "nothing"
	case ObservedTurnRan:
		return "turn-ran"
	case ObservedAccepted:
		return "accepted"
	case ObservedStored:
		return "stored"
	case ObservedConsumed:
		return "consumed"
	}
	return fmt.Sprintf("observation(%d)", int(o))
}

// Delivery is one message to push.
//
// Cursor is the contract and Body is the optimization: everything in a Body is
// expected to be re-fetchable from Cursor, so nothing here assumes the push
// worked.
type Delivery struct {
	// Cursor is the anchor this message can be re-fetched from. Required.
	Cursor string
	// Body is the message itself.
	Body string
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
	// SentBytes is the size of the message as delivered, envelope included.
	SentBytes int
	// EchoVerified reports that the target echoed the content and it matched
	// byte for byte.
	EchoVerified bool
	// Truncated reports that the message was cut to fit. Both backends
	// refuse an oversize message instead of cutting it, so this is false in
	// every path today; it exists so that a backend which ever does truncate
	// cannot do so silently.
	Truncated bool
	// Ref identifies the delivery for a later re-read: a thread and
	// submission id, or a message id.
	Ref string
}

// Deliverer pushes into the harness that launched this process.
type Deliverer interface {
	// Deliver pushes one message. The error is non-nil only when the message
	// certainly did not arrive; a nil error with ObservedNothing means the
	// write succeeded and arrival is unverified.
	Deliver(ctx context.Context, d Delivery) (Receipt, error)
	// Available reports whether the harness can be reached, with a sentence
	// explaining a negative that can be shown to a model.
	Available() (bool, string)
	// MaxIntactBytes is the largest Body that will be delivered whole. It is
	// a guaranteed floor, not the point at which delivery starts failing.
	MaxIntactBytes() (int, error)
	// Adopt latches the target from an inbound MCP request's _meta. It is a
	// no-op where the target comes from the environment. Calling it on every
	// request is free and is the recommended usage: a request without meta
	// cannot then strand the caller.
	Adopt(meta map[string]any) error
	// Close releases any connection held.
	Close() error
}

// DemonstratedIntactBytes is the largest message observed to arrive whole and
// be quoted back in full by a receiving model.
//
// It is a floor, not a ceiling. It records where an experiment stopped
// looking, not where the limit is: nothing above it has been shown to fail,
// and nothing above it has been tested. Do not split a message at this
// boundary — splitting at a boundary requires having found one.
//
// Method: numbered-checkpoint ladder with sentinels and a nonce, delivered
// over udsmsg to live Claude Code 2.1.272 sessions, each of which reported the
// highest checkpoint it could see and checked for gaps below it. 1, 4, 16, 32,
// 64, 128, 256 and 512 KB and 1,000,019 bytes — every rung intact, no cut
// found at any size (2026-09-15).
//
// Two cautions the experiment itself produced. A receiver stops participating
// long before the transport does: one session went silent after roughly 1.3 MB
// across several messages, still accepting connections but answering nothing,
// so capacity to hold is a separate limit from capacity to carry. And a
// "truncation" at the size you are probing deserves suspicion — one rung came
// back with a missing sentinel that turned out to have been deleted by the
// sender, not lost in transit.
//
// This number is NOT comparable to a limit measured on any other delivery
// path. A cut observed on one path says nothing about another: the
// notification path this was compared against truncates around 500 runes,
// which is three orders of magnitude lower.
//
// It exceeds MaxIntactBytes, and that is expected rather than a contradiction:
// see that method for why the enforced figure is deliberately lower.
//
// IT IS NOT A RECOMMENDED SIZE. "Observed to arrive whole" and "safe to send"
// are different claims, and the gap between them is the receiver's capacity to
// keep working afterwards. A message that arrives perfectly still spends a
// large and permanent fraction of a finite budget that every later message
// shares, and nothing reports that it did — the send succeeds either way. One
// receiver in this experiment stopped participating after roughly 1.3 MB
// across several messages. Size a body by what a receiver can afford to
// absorb, not by what the wire will carry; a sender choosing how much of a
// receiver's context to consume is making a decision it has no standing to
// make.
const DemonstratedIntactBytes = 1_000_000

// Option configures a Deliverer.
type Option func(*options)

type options struct{ senderName string }

// WithSenderName sets how this process is named to the harness: the attribution
// on a delivered Claude message, and the client name Codex records in thread
// metadata. It is identification, not authority — the harness derives identity
// from the socket credentials and from having spawned us, never from this.
//
// Without it the executable's own name is used, which is right for a deployed
// binary and misleading under `go run`, where it is "main".
func WithSenderName(name string) Option {
	return func(o *options) { o.senderName = name }
}

// Open returns a Deliverer for whichever harness launched this process.
//
// It never returns nil: when no harness can be reached the result reports that
// through Available, because "which harness launched me" is a state a caller has to
// explain to a model rather than an error it can retry.
func Open(opts ...Option) Deliverer {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	if o.senderName == "" {
		o.senderName = defaultSenderName()
	}
	if sock := os.Getenv(EnvClaudeSocket); sock != "" {
		return newClaude(sock, os.Getenv(EnvClaudeToken), o.senderName)
	}
	c := newCodex(o.senderName)
	// A shell-tool child of a Codex harness is told its thread at exec, the
	// same way a Claude child is told its socket. Latch it: such a process is
	// not an MCP server and will never see tool-call metadata to adopt.
	if thread := os.Getenv(EnvCodexThread); thread != "" {
		_ = c.Adopt(map[string]any{metaThreadID: thread})
	}
	return c
}

// Environment a Claude Code harness session hands its children.
const (
	// EnvClaudeSocket holds the harness session's inbox path.
	EnvClaudeSocket = "CLAUDE_CODE_MESSAGING_SOCKET"
	// EnvClaudeToken holds the child token: a credential written to no file,
	// which only a process the session spawned can hold.
	EnvClaudeToken = "CLAUDE_CODE_MESSAGING_TOKEN"
)

// metaThreadID is the key the Codex harness stamps into each MCP request's _meta.
const metaThreadID = "threadId"

// Environment a Codex harness hands its shell-tool children. MCP servers do
// not get these — their thread arrives on tool-call metadata instead — but a
// hook or a spawned command does, so a child that is not an MCP server can be
// served without Adopt ever being called.
const (
	// EnvCodexThread holds the thread the harness is running.
	EnvCodexThread = "CODEX_THREAD_ID"
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

// IsNoThreadID reports whether an Adopt error is simply "this request had no
// thread id", which a caller passing every request should ignore.
func IsNoThreadID(err error) bool { return err == errNoMeta }

// compose renders a delivery as the text the model will see.
//
// The cursor travels with the message so the model can re-fetch from it
// without the caller having to restate it, and so a truncated or lost Body
// still leaves an anchor in the transcript.
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
