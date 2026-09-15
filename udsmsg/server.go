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
	// AuthRequired rejects every line from a connection that has not
	// presented a valid token. The reference implementation leaves this off
	// by default, accepting unauthenticated frames.
	AuthRequired bool
	// PeerToken and ChildToken are the accepted tokens. Generated if empty.
	PeerToken  string
	ChildToken string
	// PublishKey writes the key file so peers can discover PeerToken.
	PublishKey bool
	// AutoStatus answers every accepted user frame that carries a reply
	// address with a "delivered" peer_message_status, as a session does. A
	// peer waiting on delivery otherwise learns nothing until its timeout.
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

// Server is a bound inbox.
type Server struct {
	cfg  Config
	ln   *net.UnixListener
	path string

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
	idle   idleSubs
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
		// Without credentials we cannot verify the peer; carry on with an
		// empty identity rather than refusing, matching the reference
		// implementation's tolerance.
		peer = &Peer{}
		s.report(fmt.Errorf("read peer credentials: %w", err))
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
			if s.cfg.AuthRequired {
				s.drop(ctx, peer, line, errors.New("invalid token; closing the connection"))
				return connDestroy
			}
			s.drop(ctx, peer, line, errors.New("invalid token; auth is optional, continuing"))
		}
		return connContinue
	}

	if s.cfg.AuthRequired && !peer.Authenticated() {
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
		if s.cfg.AutoStatus {
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
