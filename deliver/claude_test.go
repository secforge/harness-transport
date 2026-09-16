package deliver

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/secforge/harness-transport/udsmsg"
)

// parentSession stands in for the Claude Code session that launched us: a real
// inbox on a real socket, recording what arrives.
type parentSession struct {
	srv    *udsmsg.Server
	frames chan *udsmsg.Frame
}

func startParent(t *testing.T) *parentSession {
	t.Helper()
	p := &parentSession{frames: make(chan *udsmsg.Frame, 4)}
	srv, err := udsmsg.Listen(udsmsg.Config{
		Handler: udsmsg.Handler{
			OnUser: func(_ context.Context, _ *udsmsg.Peer, f *udsmsg.Frame) { p.frames <- f },
		},
	})
	if err != nil {
		t.Skipf("cannot bind an inbox here: %v", err)
	}
	srv.Start(context.Background())
	t.Cleanup(func() { srv.Close() })
	p.srv = srv
	return p
}

func (p *parentSession) received(t *testing.T) *udsmsg.Frame {
	t.Helper()
	select {
	case f := <-p.frames:
		return f
	case <-time.After(5 * time.Second):
		t.Fatal("nothing reached the parent session within 5s")
		return nil
	}
}

func TestDeliverReachesTheParentSession(t *testing.T) {
	p := startParent(t)
	d := newClaude(p.srv.Path(), "test-token", "test-client", "", udsmsg.ModePrompting)

	r, err := d.Deliver(context.Background(), Delivery{Cursor: "c-99", Body: "a relayed message"})
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}

	f := p.received(t)
	text := f.Text()
	if !strings.Contains(text, "a relayed message") {
		t.Errorf("the body did not arrive: %q", text)
	}
	if !strings.Contains(text, "c-99") {
		t.Errorf("the cursor did not arrive: %q", text)
	}
	// Attributed, so the receiving session shows who delivered it.
	if _, _, wrapped := udsmsg.Unwrap(text); !wrapped {
		t.Errorf("the message should carry attribution: %q", text)
	}
	if r.Ref != f.MsgID {
		t.Errorf("Ref = %q, want the msg_id %q for a later re-read", r.Ref, f.MsgID)
	}
}

// The single most important assertion in this package: a Claude delivery must
// never claim more than it observed.
func TestClaudeNeverClaimsArrival(t *testing.T) {
	p := startParent(t)
	d := newClaude(p.srv.Path(), "test-token", "test-client", "", udsmsg.ModePrompting)

	r, err := d.Deliver(context.Background(), Delivery{Cursor: "c", Body: "x"})
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	p.received(t)

	if r.Observation != ObservedNothing {
		t.Fatalf("Observation = %v; this transport sends no receipt, so nothing stronger can be honest", r.Observation)
	}
	if r.EchoVerified {
		t.Error("EchoVerified must be false: nothing was echoed")
	}
	if !strings.Contains(r.Detail, "unverified") {
		t.Errorf("Detail must say arrival is unverified, got %q", r.Detail)
	}
	for _, overclaim := range []string{"delivered to", "confirmed", "guaranteed"} {
		if strings.Contains(strings.ToLower(r.Detail), overclaim) {
			t.Errorf("Detail overclaims with %q: %s", overclaim, r.Detail)
		}
	}
}

// An oversize message is refused, never cut: the failure this package exists
// to avoid is content that arrives silently incomplete.
func TestOversizeIsRefusedNotTruncated(t *testing.T) {
	p := startParent(t)
	d := newClaude(p.srv.Path(), "test-token", "test-client", "", udsmsg.ModePrompting)
	max, _ := d.MaxIntactBytes()

	r, err := d.Deliver(context.Background(), Delivery{Cursor: "c", Body: strings.Repeat("x", max+1)})
	if err == nil {
		t.Fatal("an oversize message must be refused")
	}
	if r.Truncated {
		t.Error("nothing should ever be reported as truncated: the message was refused whole")
	}
	if !strings.Contains(err.Error(), "cursor") {
		t.Errorf("the error should point at the cursor fallback: %v", err)
	}
	select {
	case f := <-p.frames:
		t.Errorf("a refused message must not be sent at all, got %q", f.Text())
	case <-time.After(250 * time.Millisecond):
	}
}

// A message just under the limit goes whole — the ceiling is a real working
// size, not a number that fails just below itself.
func TestLargeMessageArrivesIntact(t *testing.T) {
	p := startParent(t)
	d := newClaude(p.srv.Path(), "test-token", "test-client", "", udsmsg.ModePrompting)

	body := "BEGIN " + strings.Repeat("payload ", 8000) + " END"
	if _, err := d.Deliver(context.Background(), Delivery{Cursor: "c", Body: body}); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	_, got, wrapped := udsmsg.Unwrap(p.received(t).Text())
	if !wrapped {
		t.Fatal("expected an attributed message")
	}
	if !strings.HasPrefix(got, "BEGIN ") || !strings.Contains(got, " END") {
		t.Error("the message did not arrive whole")
	}
}

// A gone parent is a certainty, not a silence: the caller learns the message
// did not arrive rather than having to infer it.
func TestUnreachableParentIsReportedAsCertainNonArrival(t *testing.T) {
	p := startParent(t)
	path := p.srv.Path()
	p.srv.Close()

	d := newClaude(path, "", "test-client", "", udsmsg.ModePrompting)
	ok, reason := d.Available()
	if ok {
		t.Fatal("a closed parent inbox should not report as available")
	}
	if !strings.Contains(reason, "no longer listening") {
		t.Errorf("reason = %q, want a sentence a model can be shown", reason)
	}
	if _, err := d.Deliver(context.Background(), Delivery{Cursor: "c", Body: "x"}); err == nil {
		t.Error("delivering to a gone parent must fail rather than look like a success")
	}
}

// Without an inherited socket there is no parent, and the package must not go
// looking for one.
func TestNoInheritedSocketMeansNoParent(t *testing.T) {
	d := newClaude("", "", "test-client", "", udsmsg.ModePrompting)
	ok, reason := d.Available()
	if ok {
		t.Fatal("no socket means no parent")
	}
	if !strings.Contains(reason, "not launched by a Claude Code harness") {
		t.Errorf("reason = %q", reason)
	}
}

// With the token inherited, the session is reachable and says so plainly.
func TestAnInheritedTokenMakesTheSessionReachable(t *testing.T) {
	p := startParent(t)
	ok, reason := newClaude(p.srv.Path(), "cafebabe", "test-client", "", udsmsg.ModePrompting).Available()
	if !ok || !strings.Contains(reason, "reachable") {
		t.Errorf("with a child token: ok=%v reason=%q", ok, reason)
	}
}

// Delivering without the inherited token is refused outright rather than
// attempted: a harness that requires authentication would destroy the
// connection and say nothing, so the failure is made local and explicit
// instead of remote and silent.
func TestNoTokenMeansNoDelivery(t *testing.T) {
	p := startParent(t)
	d := newClaude(p.srv.Path(), "", "test-client", "", udsmsg.ModePrompting)

	ok, reason := d.Available()
	if ok {
		t.Error("with no inherited token there is nothing we can deliver to safely")
	}
	if !strings.Contains(reason, "no child token") {
		t.Errorf("reason = %q, want it to name the missing token", reason)
	}
	if _, err := d.Deliver(context.Background(), Delivery{Cursor: "c", Body: "x"}); err == nil {
		t.Fatal("delivery without a token must be refused, not attempted")
	}
	select {
	case f := <-p.frames:
		t.Errorf("nothing should have been sent, got %q", f.Text())
	case <-time.After(250 * time.Millisecond):
	}
}

// A reply address makes a delivery answerable with the harness's ordinary
// reply instead of a separate tool. It has to reach both places: the frame,
// where delivery status goes, and the envelope, which is what the model sees.
func TestAReplyAddressReachesFrameAndEnvelope(t *testing.T) {
	p := startParent(t)
	const inbox = "uds:/run/user/0/cc-socks/4242-a1b2c3d4.sock"

	if _, err := newClaude(p.srv.Path(), "test-token", "test-client", inbox, udsmsg.ModePrompting).
		Deliver(context.Background(), Delivery{Cursor: "c", Body: "answerable"}); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	f := p.received(t)
	if f.From != inbox {
		t.Errorf("frame from = %q, want the reply address — delivery status goes there", f.From)
	}
	cs, _, wrapped := udsmsg.Unwrap(f.Text())
	if !wrapped || cs.From != inbox {
		t.Errorf("envelope from = %q, want the reply address — this is what the model replies to", cs.From)
	}
}

// The default stays one-way: a caller that names no inbox has nothing to be
// answered on, and an envelope claiming otherwise would point nowhere.
func TestWithoutAReplyAddressTheDeliveryIsOneWay(t *testing.T) {
	p := startParent(t)
	if _, err := newClaude(p.srv.Path(), "test-token", "test-client", "", udsmsg.ModePrompting).
		Deliver(context.Background(), Delivery{Cursor: "c", Body: "one-way"}); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	f := p.received(t)
	if f.From != "" {
		t.Errorf("frame from = %q, want empty", f.From)
	}
	if cs, _, _ := udsmsg.Unwrap(f.Text()); cs.From != "" {
		t.Errorf("envelope from = %q, want empty", cs.From)
	}
}
