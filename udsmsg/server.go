package udsmsg

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ErrLineTooLong is reported when a line exceeds MaxLineBytes. The receiver
// drops the whole connection in that case, not just the offending line.
var ErrLineTooLong = errors.New("line exceeds the 1 MiB cap")

// Handler receives dispatched frames. Every field is optional; a nil callback
// means the frame is accepted and discarded. Each callback gets the verified
// peer identity and the frame, whose Raw field holds the line as received.
type Handler struct {
	OnUser                   func(ctx context.Context, p *Peer, f *Frame)
	OnRename                 func(ctx context.Context, p *Peer, f *Frame)
	OnPeerMessageStatus      func(ctx context.Context, p *Peer, f *Frame)
	OnNotifyWhenIdle         func(ctx context.Context, p *Peer, f *Frame)
	OnPeerIdleNotice         func(ctx context.Context, p *Peer, f *Frame)
	OnYieldArtifactReplies   func(ctx context.Context, p *Peer, f *Frame)
	OnUnyieldArtifactReplies func(ctx context.Context, p *Peer, f *Frame)
	OnArtifactRepliesYielded func(ctx context.Context, p *Peer, f *Frame)

	// OnUnknown receives frames with an unhandled type or control action,
	// which the reference implementation only logs.
	OnUnknown func(ctx context.Context, p *Peer, f *Frame)
	// OnDrop reports a frame or connection the server refused, with the
	// reason: a session_id mismatch, a failed auth, an unparsable line.
	OnDrop func(ctx context.Context, p *Peer, line []byte, reason error)
	// OnError reports accept and I/O failures.
	OnError func(err error)
}

// Config configures an inbox.
type Config struct {
	// Path is the socket to bind. Empty allocates one in the first usable
	// standard socket directory, named "<pid>-<8 hex>.sock" so it cannot be
	// mistaken for a real session's inbox.
	Path string
	// SessionID, when set, is enforced: a frame carrying a different
	// session_id is dropped. A frame without one is always accepted.
	SessionID string
	// RequireAuth rejects every line from a connection that has not
	// presented a valid token. The reference implementation leaves this off
	// by default, accepting unauthenticated frames.
	RequireAuth bool
	// PeerToken and ChildToken are the accepted tokens. Generated if empty.
	PeerToken  string
	ChildToken string
	// AllowUnidentifiedPeers accepts connections whose credentials the
	// kernel will not report — which is every connection on a platform
	// without SO_PEERCRED or LOCAL_PEERCRED. Off by default: identity here
	// is a pid and a start time, so an unidentified peer cannot be held to
	// anything a caller might be checking.
	AllowUnidentifiedPeers bool
	// PublishKey writes the key file so peers can discover PeerToken.
	PublishKey bool
	// ModeSource says where this inbox's permission posture comes from: not
	// set, so no mode is asserted; derived and required; or derived where
	// that is possible. See ModeSource for the three.
	//
	// It names a SOURCE and can never name a posture. The posture is a value
	// a receiver acts on and cannot verify, and a struct field is the thing
	// people fill in — so the only way to assert one here is to have it
	// derived, and the only way to claim one is the function that says so in
	// its name (Server.AssertModeUnverified).
	ModeSource ModeSource
	// AutoStatus answers every accepted user frame that carries a reply
	// address with a "delivered" peer_message_status. A peer waiting on
	// delivery otherwise learns nothing until its timeout.
	//
	// Do NOT turn this on for an inbox that Claude Code sessions send to. A
	// session emits "delivered" only after a message was HELD and then
	// approved, so its sender renders any delivered as "approved and released
	// after approval". An inbox that acks every accept therefore reports a
	// hold and an approval that never happened, in the sender's terminal,
	// once per message — and no setting on either side will make it stop,
	// because nothing was ever held.
	//
	// That cost four sessions an hour of measuring a gate that did not exist.
	// It is off by default and should stay off wherever the senders are
	// sessions; for peers of our own, prefer an explicit Server.Ack on a
	// path where "delivered" means something.
	AutoStatus bool
	// TrackIdle records notify_when_idle subscriptions taken out against us,
	// for Server.GoIdle to notify. Without it the request is dispatched to
	// the handler and forgotten, and the subscriber waits for a notice that
	// never comes.
	TrackIdle bool
	// FirstLineTimeout overrides the deadline for a connection's first
	// complete line. Zero uses FirstLineTimeout.
	FirstLineTimeout time.Duration
	Handler          Handler
	Logger           *log.Logger
}

// ModeSource says where an inbox's asserted permission posture comes from.
// There is no value meaning "whatever the caller says": a posture is either
// established or absent.
type ModeSource int

const (
	// ModeSourceNone asserts no posture. A frame with no from_mode is held
	// only by a receiver in bypass, so this costs a hold at worst.
	ModeSourceNone ModeSource = iota
	// ModeSourceDerived reads the posture from the spawning session and
	// asserts nothing if it cannot, binding either way. This is what a
	// cross-platform caller wants: detection works on Linux and errors on
	// darwin and windows, and the platforms where it works are exactly the
	// ones where it helps. Failing to detect costs a hold; failing to bind
	// would cost the whole return path.
	ModeSourceDerived
	// ModeSourceDerivedRequired refuses to bind unless the posture can be
	// established. For a caller whose feature is meaningless without parity,
	// not starting beats starting silently without it — but on any platform
	// with no /proc that is every time, so it is opt-in for exactly that
	// caller rather than the default.
	ModeSourceDerivedRequired
)

// Server is a bound inbox.
type Server struct {
	cfg  Config
	ln   *net.UnixListener
	path string

	// mode is the posture we assert on frames we originate. Empty asserts
	// nothing, which is the honest default: a receiver holds only on a
	// MISMATCH, so a frame that claims no mode is not held.
	mode Mode

	mu     sync.Mutex
	closed bool
	// heldMsgIDs records the messages this inbox told a sender were HELD.
	// "delivered" means "the hold you were told about has been released" and
	// nothing else, so it is only ours to send for one of these.
	heldMsgIDs map[string]bool
	wg         sync.WaitGroup
	idle       idleSubs
}

// Listen binds an inbox and, if configured, publishes its key file.
func Listen(cfg Config) (*Server, error) {
	if cfg.PeerToken == "" {
		cfg.PeerToken = NewToken()
	}
	if cfg.ChildToken == "" {
		cfg.ChildToken = NewToken()
	}
	path := cfg.Path
	if path == "" {
		p, err := allocSocketPath()
		if err != nil {
			return nil, err
		}
		path = p
	} else if err := CheckDir(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("socket directory: %w", err)
	}

	// A stale socket from a crashed run would block the bind.
	if fi, err := os.Stat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
		os.Remove(path)
	}
	addr, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		return nil, err
	}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("bind %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, err
	}
	s := &Server{cfg: cfg, ln: ln, path: path}

	if cfg.ModeSource != ModeSourceNone {
		m, err := DetectParentMode()
		switch {
		case err == nil:
			s.mode = m
		case cfg.ModeSource == ModeSourceDerivedRequired:
			ln.Close()
			os.Remove(path)
			return nil, fmt.Errorf("ModeSourceDerivedRequired: %w", err)
		default:
			// Bind anyway, asserting nothing. Worth saying out loud: the
			// symptom otherwise is someone else's message being held, seen
			// from the wrong side of the socket.
			s.logf("asserting no permission mode (%v); frames we originate may be held by a bypass-mode receiver", err)
		}
	}

	if cfg.PublishKey {
		k := &Key{PeerToken: cfg.PeerToken}
		if ps, err := ProcStart(os.Getpid()); err == nil {
			k.ProcStart = ps
		}
		if pd, err := PIDDomain(os.Getpid()); err == nil {
			k.PIDDomain = pd
		}
		if err := WriteKey(os.Getpid(), path, k); err != nil {
			s.Close()
			return nil, fmt.Errorf("publish key file: %w", err)
		}
	}
	return s, nil
}

// allocSocketPath picks the first usable standard directory and a socket name
// that carries our pid plus a discriminator.
// allocSocketPath places our inbox in a standard socket directory, and that
// location is load-bearing rather than tidy.
//
// A receiver validates a claimed reply address before it will send anything
// there. An address in the SAME DIRECTORY as the receiver's own socket is
// accepted on the strength of ending in .sock and nothing else; an address
// anywhere else has to clear a verified peer pid, a file-name pattern, one of
// the standard directories, and a uid written into the path matching one the
// receiver accepts. Rejection is silent — it logs on its side and simply does
// not send the status frame.
//
// So moving this to a temp dir would not fail loudly, it would cost every
// status frame with no error anywhere.
func allocSocketPath() (string, error) {
	var disc [4]byte
	if _, err := rand.Read(disc[:]); err != nil {
		return "", err
	}
	name := fmt.Sprintf("%d-%08x.sock", os.Getpid(), binary.BigEndian.Uint32(disc[:]))

	dirs := SocketDirs()
	for _, dir := range dirs {
		if CheckDir(dir) == nil {
			return filepath.Join(dir, name), nil
		}
	}
	// Nothing usable exists yet; create the preferred directory.
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			continue
		}
		if err := os.Chmod(dir, 0o700); err != nil {
			continue
		}
		if CheckDir(dir) == nil {
			return filepath.Join(dir, name), nil
		}
	}
	return "", fmt.Errorf("no usable socket directory among %v", dirs)
}

// Path returns the bound socket path.
func (s *Server) Path() string { return s.path }

// Addr returns the inbox as a uds: reply address, ready to use as a From.
func (s *Server) Addr() string { return UDSAddress(s.path) }

// PeerToken returns the token published for other sessions.
func (s *Server) PeerToken() string { return s.cfg.PeerToken }

// Serve accepts connections until the context is cancelled or Close is called.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	for {
		conn, err := s.ln.AcceptUnix()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				s.wg.Wait()
				return nil
			}
			s.report(err)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(ctx, conn)
		}()
	}
}

// Start runs Serve in the background and returns immediately.
func (s *Server) Start(ctx context.Context) {
	go func() {
		if err := s.Serve(ctx); err != nil {
			s.report(err)
		}
	}()
}

// Close stops the inbox and removes the socket and any published key file.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	err := s.ln.Close()
	os.Remove(s.path)
	if s.cfg.PublishKey {
		RemoveKey(os.Getpid(), s.path)
	}
	return err
}

func (s *Server) report(err error) {
	if s.cfg.Handler.OnError != nil {
		s.cfg.Handler.OnError(err)
	} else if s.cfg.Logger != nil {
		s.cfg.Logger.Printf("udsmsg: %v", err)
	}
}

func (s *Server) drop(ctx context.Context, p *Peer, line []byte, reason error) {
	if s.cfg.Handler.OnDrop != nil {
		s.cfg.Handler.OnDrop(ctx, p, line, reason)
	} else if s.cfg.Logger != nil {
		s.cfg.Logger.Printf("udsmsg: dropped a frame: %v", reason)
	}
}

func (s *Server) handleConn(ctx context.Context, conn *net.UnixConn) {
	defer conn.Close()

	peer, err := peerCred(conn)
	if err != nil {
		// Identity in this protocol IS the kernel's answer — a pid and a
		// start time — so a connection we cannot identify is one we cannot
		// hold to anything. Carrying on with an empty Peer would hand every
		// caller a PID of 0 that reads like a process, which on a platform
		// with no such call would be every connection, silently.
		//
		// So it is refused unless the caller has said otherwise. That is a
		// decision about what an absent identity means, and it belongs to
		// whoever is enforcing something with it rather than to this file.
		if !s.cfg.AllowUnidentifiedPeers {
			s.report(fmt.Errorf("refusing a connection whose peer could not be identified "+
				"(set AllowUnidentifiedPeers to accept these): %w", err))
			return
		}
		peer = &Peer{}
		s.report(fmt.Errorf("accepting an unidentified peer: %w", err))
	}
	peer.Addr = s.path
	peer.SelfSent = int(peer.PID) == os.Getpid()

	// The first complete line must arrive inside the deadline.
	deadline := s.cfg.FirstLineTimeout
	if deadline <= 0 {
		deadline = FirstLineTimeout
	}
	_ = conn.SetReadDeadline(time.Now().Add(deadline))
	first := true

	r := bufio.NewReaderSize(conn, 64<<10)
	for {
		line, complete, err := readLine(r, MaxLineBytes)
		if errors.Is(err, ErrLineTooLong) {
			s.drop(ctx, peer, nil, ErrLineTooLong)
			return
		}
		if len(line) > 0 {
			if first {
				// A complete first line arrived; the deadline has served
				// its purpose.
				_ = conn.SetReadDeadline(time.Time{})
			}
			consumed := s.dispatch(ctx, peer, line, first)
			first = false
			if consumed == connDestroy {
				return
			}
		}
		if err != nil {
			if !complete && err != io.EOF && !errors.Is(err, net.ErrClosed) {
				s.report(err)
			}
			return
		}
	}
}

type dispatchResult int

const (
	connContinue dispatchResult = iota
	connDestroy
)

// dispatch handles one line. isFirst allows the auth frame, which is consumed
// here and never passed to a handler.
func (s *Server) dispatch(ctx context.Context, peer *Peer, line []byte, isFirst bool) dispatchResult {
	f, err := DecodeFrame(line)
	if err != nil {
		// A parse failure skips that line only.
		s.drop(ctx, peer, line, err)
		return connContinue
	}
	if f.Type == "" {
		s.drop(ctx, peer, line, errors.New("frame has no type"))
		return connContinue
	}

	if isFirst && f.IsAuth() {
		switch {
		case subtle.ConstantTimeCompare([]byte(f.Token), []byte(s.cfg.PeerToken)) == 1:
			peer.Auth = AuthPeer
		case subtle.ConstantTimeCompare([]byte(f.Token), []byte(s.cfg.ChildToken)) == 1:
			peer.Auth = AuthChild
		default:
			if s.cfg.RequireAuth {
				s.drop(ctx, peer, line, errors.New("invalid token; closing the connection"))
				return connDestroy
			}
			s.drop(ctx, peer, line, errors.New("invalid token; auth is optional, continuing"))
		}
		return connContinue
	}

	if s.cfg.RequireAuth && !peer.Authenticated() {
		s.drop(ctx, peer, line, errors.New("dropped a frame from a connection that did not authenticate; closing it"))
		return connDestroy
	}

	if s.cfg.SessionID != "" && f.SessionID != "" && f.SessionID != s.cfg.SessionID {
		s.drop(ctx, peer, line, fmt.Errorf("session_id mismatch (got %s, expected %s)", f.SessionID, s.cfg.SessionID))
		return connContinue
	}

	h := &s.cfg.Handler
	switch f.Type {
	case TypeUser:
		call(ctx, h.OnUser, h.OnUnknown, peer, f)
		if s.cfg.AutoStatus && s.wasHeld(f.MsgID) {
			// Reporting happens off the read loop: it dials the sender back,
			// and that must not stall the connection we are reading.
			s.wg.Add(1)
			go func() {
				defer s.wg.Done()
				if err := s.Ack(ctx, f); err != nil {
					s.report(fmt.Errorf("acknowledge %s: %w", f.MsgID, err))
				}
			}()
		}
	case TypeControl:
		switch f.Action {
		case ActionRename:
			if f.Name == "" {
				s.drop(ctx, peer, line, errors.New("rename without a name"))
				return connContinue
			}
			call(ctx, h.OnRename, h.OnUnknown, peer, f)
		case ActionPeerMessageStatus:
			call(ctx, h.OnPeerMessageStatus, h.OnUnknown, peer, f)
		case ActionNotifyWhenIdle:
			if s.cfg.TrackIdle {
				if err := s.Subscribe(f); err != nil {
					s.drop(ctx, peer, line, fmt.Errorf("notify_when_idle refused: %w", err))
					return connContinue
				}
			}
			call(ctx, h.OnNotifyWhenIdle, h.OnUnknown, peer, f)
		case ActionPeerIdleNotice:
			call(ctx, h.OnPeerIdleNotice, h.OnUnknown, peer, f)
		case ActionYieldArtifactReplies:
			call(ctx, h.OnYieldArtifactReplies, h.OnUnknown, peer, f)
		case ActionUnyieldArtifactReplies:
			call(ctx, h.OnUnyieldArtifactReplies, h.OnUnknown, peer, f)
		case ActionArtifactRepliesYielded:
			call(ctx, h.OnArtifactRepliesYielded, h.OnUnknown, peer, f)
		default:
			call(ctx, nil, h.OnUnknown, peer, f)
		}
	default:
		call(ctx, nil, h.OnUnknown, peer, f)
	}
	return connContinue
}

func call(ctx context.Context, fn, fallback func(context.Context, *Peer, *Frame), p *Peer, f *Frame) {
	if fn != nil {
		fn(ctx, p, f)
		return
	}
	if fallback != nil {
		fallback(ctx, p, f)
	}
}

// readLine reads one newline-terminated line, capped at max bytes.
//
// It returns complete == false for a trailing partial line, which the
// reference implementation still parses when the connection closes.
func readLine(r *bufio.Reader, max int) (line []byte, complete bool, err error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(buf)+len(chunk) > max {
			return nil, false, ErrLineTooLong
		}
		buf = append(buf, chunk...)
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			return buf, false, err // trailing buffer, parsed on close
		}
		return buf[:len(buf)-1], true, nil
	}
}

// logf reports something worth knowing that is not a dropped frame or an I/O
// error. Silent when no Logger is configured.
func (s *Server) logf(format string, args ...any) {
	if s.cfg.Logger != nil {
		s.cfg.Logger.Printf("udsmsg: "+format, args...)
	}
}

// Mode is the permission posture this inbox asserts on the frames it
// originates. Empty means it asserts none.
func (s *Server) Mode() Mode { return s.mode }

// AssertModeUnverified makes this inbox claim m without establishing it.
//
// Nothing checks the claim: a receiver holds a frame whose mode mismatches
// its own and lets a matching one through, so a claim chosen to match is a
// claim that clears the gate. Where the posture is a user's decision, that
// makes asserting it upward a way of spending permission the user did not
// give. Prefer Config.ModeSource, which reads the posture instead, and reach
// for this only where the caller genuinely knows something the parent's
// command line cannot show.
//
// The honest path and this one differ only by which function was called, and
// that difference is invisible afterwards — so it is logged. An inbox whose
// posture was claimed rather than established should say so somewhere other
// than in the caller's memory.
func (s *Server) AssertModeUnverified(m Mode) {
	s.mode = m
	s.logf("permission mode %q asserted by the caller, not derived from the spawning session", m)
}
