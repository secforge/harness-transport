package udsmsg

import (
	"context"
	"testing"
	"time"
)

// listenTest binds an inbox for a test and closes it afterwards.
func listenTest(t *testing.T, cfg Config) *Server {
	t.Helper()
	s, err := Listen(cfg)
	if err != nil {
		t.Skipf("cannot bind an inbox here: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	s.Start(context.Background())
	return s
}

func recv(t *testing.T, ch <-chan *Frame) *Frame {
	t.Helper()
	select {
	case f := <-ch:
		return f
	case <-time.After(5 * time.Second):
		t.Fatal("nothing arrived within 5s")
		return nil
	}
}

// A sender learns nothing from a listener that never reports, so an accepted
// message is answered on the sender's own inbox.
func TestAutoStatusAcknowledgesToTheSender(t *testing.T) {
	ctx := context.Background()

	got := make(chan *Frame, 4)
	sender := listenTest(t, Config{Handler: Handler{
		OnPeerMessageStatus: func(_ context.Context, _ *Peer, f *Frame) { got <- f },
	}})
	receiver := listenTest(t, Config{AutoStatus: true})

	c, err := Dial(ctx, Target{SocketPath: receiver.Path(), Unauthenticated: true})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	msgID, err := c.SendUser(User{Text: "hello", From: sender.Addr()})
	if err != nil {
		t.Fatalf("send: %v", err)
	}

	f := recv(t, got)
	if f.Status != StatusDelivered {
		t.Errorf("status = %q, want %q", f.Status, StatusDelivered)
	}
	if f.OrigMsgID != msgID {
		t.Errorf("orig_msg_id = %q, want %q", f.OrigMsgID, msgID)
	}
	if f.Reason != ReasonDelivered {
		t.Errorf("reason = %q, want the fixed prose", f.Reason)
	}
	if f.From != receiver.Addr() {
		t.Errorf("from = %q, want the receiver's address %q", f.From, receiver.Addr())
	}
}

// A message that asked for nothing back must not provoke a connection.
func TestAckWithoutReplyAddressIsANoOp(t *testing.T) {
	s := listenTest(t, Config{})
	if err := s.Ack(context.Background(), &Frame{Type: TypeUser, MsgID: "x"}); err != nil {
		t.Errorf("Ack without From = %v, want no error and no send", err)
	}
}

// The wire has no "refused" status: it travels as expired plus a detail.
func TestSendStatusTranslatesRefused(t *testing.T) {
	ctx := context.Background()
	got := make(chan *Frame, 1)
	sender := listenTest(t, Config{Handler: Handler{
		OnPeerMessageStatus: func(_ context.Context, _ *Peer, f *Frame) { got <- f },
	}})
	receiver := listenTest(t, Config{})

	if err := receiver.SendStatus(ctx, sender.Addr(), Status{Status: StatusRefused, OrigMsgID: "m1"}); err != nil {
		t.Fatalf("SendStatus: %v", err)
	}
	f := recv(t, got)
	if f.Status != StatusExpired || f.StatusDetail != "refused" {
		t.Errorf("refused should travel as expired/refused, got %q/%q", f.Status, f.StatusDetail)
	}
}

// A subscription is one-shot: the notice fires once and the subscriber is
// forgotten, so a second turn does not notify again.
func TestGoIdleNotifiesSubscribersOnce(t *testing.T) {
	ctx := context.Background()
	got := make(chan *Frame, 4)
	subscriber := listenTest(t, Config{Handler: Handler{
		OnPeerIdleNotice: func(_ context.Context, _ *Peer, f *Frame) { got <- f },
	}})
	receiver := listenTest(t, Config{TrackIdle: true})

	c, err := Dial(ctx, Target{SocketPath: receiver.Path(), Unauthenticated: true})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if err := c.NotifyWhenIdle(subscriber.Addr(), "m1", ModePrompting); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for receiver.Subscribers() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if receiver.Subscribers() != 1 {
		t.Fatalf("subscribers = %d, want 1", receiver.Subscribers())
	}

	if err := receiver.GoIdle(ctx, StateIdle, "finished the turn"); err != nil {
		t.Fatalf("GoIdle: %v", err)
	}
	f := recv(t, got)
	if f.OrigMsgID != "m1" || f.State != string(StateIdle) || f.Detail != "finished the turn" {
		t.Errorf("notice = %+v, want it to carry the subscription's msg_id, state and detail", f)
	}
	if receiver.Subscribers() != 0 {
		t.Errorf("a one-shot subscription should be spent, %d left", receiver.Subscribers())
	}

	if err := receiver.GoIdle(ctx, StateIdle, ""); err != nil {
		t.Fatalf("second GoIdle: %v", err)
	}
	select {
	case f := <-got:
		t.Errorf("a spent subscription should not fire again, got %+v", f)
	case <-time.After(250 * time.Millisecond):
	}
}

// Notifying ourselves forever is the one subscription that must be refused.
func TestSubscribeRefusesOurOwnAddress(t *testing.T) {
	s := listenTest(t, Config{TrackIdle: true})
	if err := s.Subscribe(&Frame{From: s.Addr(), MsgID: "m1"}); err == nil {
		t.Error("a subscription pointing at this inbox should be refused")
	}
	if err := s.Subscribe(&Frame{MsgID: "m1"}); err == nil {
		t.Error("a subscription without a reply address should be refused")
	}
	if err := s.Subscribe(&Frame{From: "uds:/tmp/not-a-socket-dir/1.sock", MsgID: "m1"}); err == nil {
		t.Error("a subscription outside the socket namespace should be refused")
	}
	if s.Subscribers() != 0 {
		t.Errorf("no refused subscription should be recorded, got %d", s.Subscribers())
	}
}

// The same peer asking twice for the same message is one subscription: the
// notice is one-shot, and two notices would be a lie about two turns.
func TestSubscribeIsIdempotentPerMessage(t *testing.T) {
	s := listenTest(t, Config{TrackIdle: true})
	other := listenTest(t, Config{})
	for i := 0; i < 3; i++ {
		if err := s.Subscribe(&Frame{From: other.Addr(), MsgID: "m1"}); err != nil {
			t.Fatalf("subscribe: %v", err)
		}
	}
	if s.Subscribers() != 1 {
		t.Errorf("subscribers = %d, want 1", s.Subscribers())
	}
}
