package udsmsg

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
)

// The receiving half of the protocol is not just listening. A session answers
// on the sender's own inbox: a peer_message_status for what became of the
// prompt, and, for a peer that subscribed, one peer_idle_notice when the turn
// ends. A listener that never sends either is indistinguishable from one that
// ignored the message — its peers block until their timeouts instead of
// learning what happened.
//
// One asymmetry to know before turning AutoStatus on: a session emits
// peer_message_status only on the hold path — held, denied, then delivered
// once an approval goes through. An ordinary accepted message is reported on
// by nobody, which is why waiting for a "delivered" that a same-mode peer
// never sends will simply time out. Acknowledging everything is therefore
// more talkative than a session, not a faithful imitation of one; it is
// useful between our own processes, where the alternative is silence.

// Fixed prose the reference implementation sends with a status. A peer may
// show these to its user, so they are reproduced rather than paraphrased.
const (
	ReasonHeld      = "Your message is held for the recipient user's approval before it reaches their Claude session (permission-mode parity)"
	ReasonDenied    = "The recipient user declined your message; it was not delivered"
	ReasonDelivered = "Your message was delivered to the recipient's session"
	ReasonDropped   = "Your message was dropped by the recipient's session"
)

// IdleState is the state a peer_idle_notice reports.
type IdleState string

const (
	// StateIdle is the ordinary end of a turn: nothing queued. A session
	// debounces it, and holds it back while parked or held items remain.
	StateIdle IdleState = "idle"
	// StateExited is sent during shutdown — but a session exiting while
	// genuinely idle sends StateIdle instead, so this is narrower than
	// "the session is gone".
	StateExited IdleState = "exited"
	// StateUnavailable means the subscription cannot be served at all: no
	// notice channel, or policy refuses it.
	StateUnavailable IdleState = "unavailable"
)

// DialAddress connects to a reply address, presenting a token when the
// addressed socket has a key file published for it.
//
// A subscriber is named by address, not by pid, so the pid is recovered from
// the socket name — the only place it is recorded. An opaque 16-hex name
// carries none, and the connection is then unauthenticated, which the receiver
// accepts by default.
func DialAddress(ctx context.Context, addr string) (*Client, error) {
	path, err := ResolveReplyAddr(addr)
	if err != nil {
		return nil, err
	}
	t := Target{SocketPath: path}
	if pid, ok := PIDFromSocketName(filepath.Base(path)); ok {
		t.PID = pid
		if k, err := ReadKey(pid, path); err == nil && k != nil {
			t.Token, t.ProcStart = k.PeerToken, k.ProcStart
		}
	}
	// Dial refuses a tokenless connection, and this is the one place that
	// asks for the exemption rather than being a caller who forgot. We are
	// answering an address a peer gave us; if it published no key file there
	// is no token in existence to present, and no way to obtain one. The
	// choice is between replying unauthenticated and never replying at all —
	// and the peer chose that by not publishing.
	t.Unauthenticated = t.Token == ""
	return Dial(ctx, t)
}

// Status describes what became of a message we were sent.
type Status struct {
	// Status is one of the StatusXxx constants.
	Status string
	// OrigMsgID is the msg_id of the message being reported on. Without it
	// the sender cannot correlate the report.
	OrigMsgID string
	// Detail and Reason are optional prose; Reason defaults to the fixed
	// wording for Status.
	Detail string
	Reason string
}

// SendStatus reports what became of a message, to the address that sent it.
//
// The wire has no "refused" status: it travels as expired with the detail
// "refused", which this translates so callers can use the constant.
func (s *Server) SendStatus(ctx context.Context, to string, st Status) error {
	if to == "" {
		return fmt.Errorf("no address to report to")
	}
	if st.Status == StatusRefused {
		st.Status, st.Detail = StatusExpired, "refused"
	}
	if st.Reason == "" {
		st.Reason = defaultReason(st.Status)
	}
	c, err := DialAddress(ctx, to)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.SendControl(&Frame{
		Action:       ActionPeerMessageStatus,
		Status:       st.Status,
		StatusDetail: st.Detail,
		Reason:       st.Reason,
		OrigMsgID:    st.OrigMsgID,
		From:         s.Addr(),
	})
}

// Ack reports a received frame as delivered, to whoever sent it. A frame with
// no reply address is a no-op: the sender asked for nothing back.
func (s *Server) Ack(ctx context.Context, f *Frame) error {
	if f.From == "" {
		return nil
	}
	return s.SendStatus(ctx, f.From, Status{Status: StatusDelivered, OrigMsgID: f.MsgID})
}

func defaultReason(status string) string {
	switch status {
	case StatusHeld:
		return ReasonHeld
	case StatusDenied:
		return ReasonDenied
	case StatusDelivered:
		return ReasonDelivered
	case StatusDropped:
		return ReasonDropped
	}
	return ""
}

// idleSubs holds the one-shot idle subscriptions taken out against us.
type idleSubs struct {
	mu   sync.Mutex
	subs []idleSub
}

type idleSub struct {
	addr  string
	msgID string
	mode  Mode
}

// Subscribe records a notify_when_idle request. A request whose reply address
// is unshaped, outside the socket namespace, or points back at us is refused,
// as the reference implementation does — the last of those would have us
// notify ourselves forever.
func (s *Server) Subscribe(f *Frame) error {
	if f.From == "" {
		return fmt.Errorf("notify_when_idle without a reply address")
	}
	path, err := ResolveReplyAddr(f.From)
	if err != nil {
		return err
	}
	if path == s.path {
		return fmt.Errorf("notify_when_idle resolves to this inbox")
	}
	s.idle.mu.Lock()
	defer s.idle.mu.Unlock()
	for _, sub := range s.idle.subs {
		if sub.addr == f.From && sub.msgID == f.MsgID {
			return nil // already subscribed; the notice is one-shot either way
		}
	}
	s.idle.subs = append(s.idle.subs, idleSub{addr: f.From, msgID: f.MsgID, mode: f.FromMode})
	return nil
}

// Subscribers reports how many peers are waiting to hear that we went idle.
func (s *Server) Subscribers() int {
	s.idle.mu.Lock()
	defer s.idle.mu.Unlock()
	return len(s.idle.subs)
}

// GoIdle notifies every subscriber that our turn has ended and clears them:
// the subscription is one-shot, so a peer that wants to hear again asks again.
// Detail is the one-line summary a subscriber may be shown; pass "" to send
// none. Every subscriber is attempted even if one fails, and the first error
// is returned.
func (s *Server) GoIdle(ctx context.Context, state IdleState, detail string) error {
	s.idle.mu.Lock()
	subs := s.idle.subs
	s.idle.subs = nil
	s.idle.mu.Unlock()

	var firstErr error
	for _, sub := range subs {
		err := func() error {
			c, err := DialAddress(ctx, sub.addr)
			if err != nil {
				return err
			}
			defer c.Close()
			return c.SendControl(&Frame{
				Action:    ActionPeerIdleNotice,
				OrigMsgID: sub.msgID,
				State:     string(state),
				Detail:    detail,
				From:      s.Addr(),
				FromMode:  sub.mode,
			})
		}()
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("notify %s: %w", sub.addr, err)
		}
	}
	return firstErr
}
