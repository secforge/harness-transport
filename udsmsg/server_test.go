package udsmsg

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// collector is a Handler that funnels everything it sees into channels.
type collector struct {
	frames  chan *Frame
	peers   chan *Peer
	unknown chan *Frame
	drops   chan error
}

func newCollector() *collector {
	return &collector{
		frames:  make(chan *Frame, 8),
		peers:   make(chan *Peer, 8),
		unknown: make(chan *Frame, 8),
		drops:   make(chan error, 8),
	}
}

func (c *collector) handler() Handler {
	take := func(_ context.Context, p *Peer, f *Frame) {
		c.frames <- f
		select {
		case c.peers <- p:
		default:
		}
	}
	return Handler{
		OnUser:              take,
		OnRename:            take,
		OnPeerMessageStatus: take,
		OnNotifyWhenIdle:    take,
		OnPeerIdleNotice:    take,
		OnUnknown:           func(_ context.Context, _ *Peer, f *Frame) { c.unknown <- f },
		OnDrop:              func(_ context.Context, _ *Peer, _ []byte, err error) { c.drops <- err },
	}
}

func (c *collector) next(t *testing.T) *Frame {
	t.Helper()
	select {
	case f := <-c.frames:
		return f
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a frame")
		return nil
	}
}

func (c *collector) nextDrop(t *testing.T) error {
	t.Helper()
	select {
	case err := <-c.drops:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a drop")
		return nil
	}
}

func (c *collector) quiet(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case f := <-c.frames:
		t.Fatalf("frame delivered that should have been dropped: %s", f.Raw)
	case <-time.After(d):
	}
}

// sockDir returns a temp directory tightened to 0700, the mode a socket
// directory must have. t.TempDir honours the umask, so it is usually 0755.
func sockDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// testServer binds an inbox in a private 0700 directory.
func testServer(t *testing.T, cfg Config) (*Server, *collector) {
	t.Helper()
	c := newCollector()
	cfg.Handler = c.handler()
	if cfg.Path == "" {
		cfg.Path = filepath.Join(sockDir(t), "1.sock")
	}
	srv, err := Listen(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	srv.Start(ctx)
	t.Cleanup(func() { cancel(); srv.Close() })
	return srv, c
}

// raw opens a connection and writes bytes verbatim, bypassing the client's
// framing so malformed input can be tested.
func raw(t *testing.T, path string, b []byte) net.Conn {
	t.Helper()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(b); err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestRoundTripUserFrame(t *testing.T) {
	srv, c := testServer(t, Config{})
	cl, err := Dial(context.Background(), Target{SocketPath: srv.Path(), Token: srv.PeerToken()})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	id, err := cl.SendUser(User{Text: "hello", From: srv.Addr(), FromMode: ModePrompting})
	if err != nil {
		t.Fatal(err)
	}
	f := c.next(t)
	if f.Type != TypeUser || f.Text() != "hello" || f.MsgID != id {
		t.Fatalf("received %+v", f)
	}

	p := <-c.peers
	if int(p.PID) != os.Getpid() {
		t.Errorf("verified pid = %d, want %d", p.PID, os.Getpid())
	}
	if p.UID != uint32(os.Getuid()) {
		t.Errorf("verified uid = %d, want %d", p.UID, os.Getuid())
	}
	if p.ProcStart == "" {
		t.Error("peer start time not recorded")
	}
	if p.Auth != AuthPeer {
		t.Errorf("auth identity = %q, want %q", p.Auth, AuthPeer)
	}
	if !p.SelfSent {
		t.Error("a message from our own pid should be marked selfSent")
	}
}

func TestChildTokenIsAccepted(t *testing.T) {
	srv, c := testServer(t, Config{ChildToken: "c0ffee"})
	cl, err := Dial(context.Background(), Target{SocketPath: srv.Path(), Token: "c0ffee"})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if _, err := cl.SendUser(User{Text: "hi"}); err != nil {
		t.Fatal(err)
	}
	c.next(t)
	if p := <-c.peers; p.Auth != AuthChild {
		t.Errorf("auth identity = %q, want %q", p.Auth, AuthChild)
	}
}

func TestAuthOptionalAcceptsUnauthenticated(t *testing.T) {
	srv, c := testServer(t, Config{RequireAuth: false})
	cl, err := Dial(context.Background(), Target{SocketPath: srv.Path()}) // no token
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if _, err := cl.SendUser(User{Text: "unauthenticated"}); err != nil {
		t.Fatal(err)
	}
	if f := c.next(t); f.Text() != "unauthenticated" {
		t.Fatalf("received %+v", f)
	}
	if p := <-c.peers; p.Authenticated() {
		t.Error("peer should not be marked authenticated")
	}
}

func TestRequireAuthDropsUnauthenticated(t *testing.T) {
	srv, c := testServer(t, Config{RequireAuth: true})
	conn := raw(t, srv.Path(), []byte(`{"type":"user","message":{"role":"user","content":"x"}}`+"\n"))
	defer conn.Close()

	if err := c.nextDrop(t); !strings.Contains(err.Error(), "did not authenticate") {
		t.Errorf("drop reason = %v", err)
	}
	c.quiet(t, 200*time.Millisecond)
}

func TestRequireAuthDestroysConnectionOnBadToken(t *testing.T) {
	srv, c := testServer(t, Config{RequireAuth: true})
	conn := raw(t, srv.Path(), []byte(
		`{"type":"auth","token":"wrong"}`+"\n"+
			`{"type":"user","message":{"role":"user","content":"x"}}`+"\n"))
	defer conn.Close()

	if err := c.nextDrop(t); !strings.Contains(err.Error(), "invalid token") {
		t.Errorf("drop reason = %v", err)
	}
	// The connection is destroyed, so the following line never lands.
	c.quiet(t, 200*time.Millisecond)
}

func TestAuthFrameToleratesExtraFields(t *testing.T) {
	srv, c := testServer(t, Config{RequireAuth: true, PeerToken: "tok"})
	conn := raw(t, srv.Path(), []byte(
		`{"type":"auth","token":"tok","novel":true}`+"\n"+
			`{"type":"user","message":{"role":"user","content":"x"}}`+"\n"))
	defer conn.Close()
	if f := c.next(t); f.Text() != "x" {
		t.Fatalf("received %+v", f)
	}
}

// An auth frame is only an auth frame as the first line; later it is an
// ordinary unhandled type.
func TestAuthFrameOnlyCountsFirst(t *testing.T) {
	srv, c := testServer(t, Config{PeerToken: "tok"})
	conn := raw(t, srv.Path(), []byte(
		`{"type":"user","message":{"role":"user","content":"x"}}`+"\n"+
			`{"type":"auth","token":"tok"}`+"\n"))
	defer conn.Close()
	c.next(t)
	select {
	case f := <-c.unknown:
		if f.Type != TypeAuth {
			t.Fatalf("unknown frame = %+v", f)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a late auth frame should surface as an unhandled type")
	}
}

func TestSessionIDMismatchIsDropped(t *testing.T) {
	srv, c := testServer(t, Config{SessionID: "mine"})
	conn := raw(t, srv.Path(), []byte(
		`{"type":"user","session_id":"theirs","message":{"role":"user","content":"a"}}`+"\n"+
			`{"type":"user","session_id":"mine","message":{"role":"user","content":"b"}}`+"\n"+
			`{"type":"user","message":{"role":"user","content":"c"}}`+"\n"))
	defer conn.Close()

	if err := c.nextDrop(t); !strings.Contains(err.Error(), "session_id mismatch") {
		t.Errorf("drop reason = %v", err)
	}
	// The matching frame and the one with no session_id both get through.
	if f := c.next(t); f.Text() != "b" {
		t.Errorf("got %q, want b", f.Text())
	}
	if f := c.next(t); f.Text() != "c" {
		t.Errorf("got %q, want c", f.Text())
	}
}

func TestBadLineSkipsOnlyThatLine(t *testing.T) {
	srv, c := testServer(t, Config{})
	conn := raw(t, srv.Path(), []byte(
		"not json\n"+
			`{"type":"user","message":{"role":"user","content":"after"}}`+"\n"))
	defer conn.Close()

	if err := c.nextDrop(t); !strings.Contains(err.Error(), "parse JSON line") {
		t.Errorf("drop reason = %v", err)
	}
	if f := c.next(t); f.Text() != "after" {
		t.Errorf("got %q, want the frame following the bad line", f.Text())
	}
}

func TestTrailingLineWithoutNewlineIsParsedOnClose(t *testing.T) {
	srv, c := testServer(t, Config{})
	conn, err := net.Dial("unix", srv.Path())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte(`{"type":"user","message":{"role":"user","content":"tail"}}`)); err != nil {
		t.Fatal(err)
	}
	conn.Close() // no newline; the trailing buffer is parsed on close

	if f := c.next(t); f.Text() != "tail" {
		t.Errorf("got %q, want tail", f.Text())
	}
}

func TestOversizeLineDropsConnection(t *testing.T) {
	srv, c := testServer(t, Config{})
	conn, err := net.Dial("unix", srv.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Write more than the cap without ever completing a line.
	junk := strings.Repeat("x", 64<<10)
	for written := 0; written <= MaxLineBytes; written += len(junk) {
		if _, err := conn.Write([]byte(junk)); err != nil {
			break // the server has already hung up
		}
	}
	if err := c.nextDrop(t); !errors.Is(err, ErrLineTooLong) {
		t.Errorf("drop reason = %v, want ErrLineTooLong", err)
	}
}

func TestHandshakeDeadlineClosesIdleConnection(t *testing.T) {
	srv, c := testServer(t, Config{FirstLineTimeout: 150 * time.Millisecond})
	conn, err := net.Dial("unix", srv.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	time.Sleep(400 * time.Millisecond)
	// The server has hung up, so the line never arrives.
	conn.Write([]byte(`{"type":"user","message":{"role":"user","content":"late"}}` + "\n"))
	c.quiet(t, 300*time.Millisecond)
}

// Once a first line has arrived the deadline no longer applies.
func TestDeadlineLiftedAfterFirstLine(t *testing.T) {
	srv, c := testServer(t, Config{FirstLineTimeout: 200 * time.Millisecond})
	conn, err := net.Dial("unix", srv.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte(`{"type":"user","message":{"role":"user","content":"first"}}` + "\n"))
	if f := c.next(t); f.Text() != "first" {
		t.Fatal("first frame not received")
	}
	time.Sleep(400 * time.Millisecond)
	conn.Write([]byte(`{"type":"user","message":{"role":"user","content":"second"}}` + "\n"))
	if f := c.next(t); f.Text() != "second" {
		t.Errorf("got %q, want second", f.Text())
	}
}

func TestUnhandledTypeAndAction(t *testing.T) {
	srv, c := testServer(t, Config{})
	conn := raw(t, srv.Path(), []byte(
		`{"type":"mystery"}`+"\n"+
			`{"type":"control","action":"mystery_action"}`+"\n"))
	defer conn.Close()

	for i := 0; i < 2; i++ {
		select {
		case <-c.unknown:
		case <-time.After(2 * time.Second):
			t.Fatal("unhandled frame not surfaced")
		}
	}
}

func TestFrameWithoutTypeIsDropped(t *testing.T) {
	srv, c := testServer(t, Config{})
	conn := raw(t, srv.Path(), []byte(`{"action":"rename","name":"x"}`+"\n"))
	defer conn.Close()
	if err := c.nextDrop(t); !strings.Contains(err.Error(), "no type") {
		t.Errorf("drop reason = %v", err)
	}
}

func TestRenameWithoutNameIsDropped(t *testing.T) {
	srv, c := testServer(t, Config{})
	conn := raw(t, srv.Path(), []byte(`{"type":"control","action":"rename"}`+"\n"))
	defer conn.Close()
	if err := c.nextDrop(t); !strings.Contains(err.Error(), "rename without a name") {
		t.Errorf("drop reason = %v", err)
	}
}

func TestControlHelpers(t *testing.T) {
	srv, c := testServer(t, Config{})
	cl, err := Dial(context.Background(), Target{SocketPath: srv.Path()})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	if err := cl.Rename("new-name"); err != nil {
		t.Fatal(err)
	}
	if f := c.next(t); f.Action != ActionRename || f.Name != "new-name" {
		t.Errorf("received %+v", f)
	}
	if err := cl.Rename(""); err == nil {
		t.Error("an empty rename should be refused before it is sent")
	}

	status := &Frame{Status: StatusHeld, OrigMsgID: "m1", Reason: "awaiting approval"}
	if err := cl.SendPeerMessageStatus(status); err != nil {
		t.Fatal(err)
	}
	if f := c.next(t); f.Action != ActionPeerMessageStatus || f.Status != StatusHeld {
		t.Errorf("received %+v", f)
	}
}

// notify_when_idle needs a reply address inside the socket namespace; a
// temp-dir socket is rejected before it goes on the wire.
func TestNotifyWhenIdleValidatesReplyAddress(t *testing.T) {
	srv, _ := testServer(t, Config{})
	cl, err := Dial(context.Background(), Target{SocketPath: srv.Path()})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()

	if err := cl.NotifyWhenIdle(srv.Addr(), "m1", ModePrompting); err == nil {
		t.Error("a socket outside the standard directories should be refused")
	}
	if err := cl.NotifyWhenIdle("uds:"+filepath.Join(SocketDirs()[0], "1.sock"), "", ModePrompting); err == nil {
		t.Error("notify_when_idle without a msg_id should be refused")
	}
}

func TestSendUserRejectsUnshapedReplyAddress(t *testing.T) {
	srv, _ := testServer(t, Config{})
	cl, err := Dial(context.Background(), Target{SocketPath: srv.Path()})
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if _, err := cl.SendUser(User{Text: "x", From: "/not/an/address"}); err == nil {
		t.Error("an unshaped reply address should be refused")
	}
}

func TestCloseRemovesSocketAndKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(sockDir(t), "2.sock")

	srv, err := Listen(Config{Path: path, PublishKey: true})
	if err != nil {
		t.Fatal(err)
	}
	name, _ := KeyFileName(os.Getpid(), path)
	if _, err := os.Stat(filepath.Join(SessionsDir(), name)); err != nil {
		t.Fatalf("key file not published: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("socket not bound: %v", err)
	}

	srv.Close()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("socket left behind after Close")
	}
	if _, err := os.Stat(filepath.Join(SessionsDir(), name)); !os.IsNotExist(err) {
		t.Error("key file left behind after Close")
	}
	if err := srv.Close(); err != nil {
		t.Errorf("second Close = %v, want nil", err)
	}
}

func TestListenRefusesLooseDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "loose")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(Config{Path: filepath.Join(dir, "3.sock")}); err == nil {
		t.Error("binding in a world-readable directory should be refused")
	}
}

func TestListenReplacesStaleSocket(t *testing.T) {
	path := filepath.Join(sockDir(t), "4.sock")
	first, err := Listen(Config{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a crash: the process goes away but the socket file survives.
	first.ln.SetUnlinkOnClose(false)
	first.ln.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatal("expected a stale socket file")
	}
	second, err := Listen(Config{Path: path})
	if err != nil {
		t.Fatalf("rebinding over a stale socket = %v", err)
	}
	second.Close()
}

func TestAutoAllocatedPathIsDiscriminated(t *testing.T) {
	srv, err := Listen(Config{})
	if err != nil {
		t.Skipf("no usable standard socket directory: %v", err)
	}
	defer srv.Close()
	base := filepath.Base(srv.Path())
	if !ValidSocketName(base) {
		t.Errorf("auto-allocated name %q is not an acceptable socket name", base)
	}
	if !strings.Contains(base, "-") {
		t.Errorf("auto-allocated name %q lacks the discriminator that keeps it "+
			"distinct from a real session inbox", base)
	}
	if _, err := ResolveReplyAddr(srv.Addr()); err != nil {
		t.Errorf("auto-allocated inbox is not a usable reply address: %v", err)
	}
}
