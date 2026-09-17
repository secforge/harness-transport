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
	OnUser func(ctx context.Context, p *Peer, f *Frame)

	// OnUnknown receives a frame this package does not decode: a control
	// frame, or a type it does not know. Sessions send frames this package
	// deliberately does not model, so they arrive here with Raw intact rather
	// than being dropped.
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
	// RequireAuth rejects every line from a connection that has not
	// presented a valid token.
	RequireAuth bool
	// AllowUnidentifiedPeers accepts connections the kernel will not name —
	// every connection on a platform without SO_PEERCRED. Off by default,
	// since an unidentified peer cannot be checked against anything.
	AllowUnidentifiedPeers bool
	// PublishKey writes the key file so peers can discover PeerToken.
	PublishKey bool
	// ModeSource says where this inbox's permission posture comes from:
	// nowhere, or derived from the spawning session. It names a SOURCE and
	// cannot name a posture, so nothing here can state one outright.
	ModeSource ModeSource
	// FirstLineTimeout overrides the deadline for a connection's first
	// complete line. Zero uses FirstLineTimeout.
	//
	// Unused by callers, and kept — with Path above — as the seam that makes
	// the documented deadline testable without waiting 30 seconds.
	FirstLineTimeout time.Duration
	Handler          Handler
}

// ModeSource says where an inbox's permission posture comes from. There is no
// value meaning "whatever the caller says": it is established or absent.
type ModeSource int

const (
	// ModeSourceNone asserts no posture, which may cost a hold — cheaper
	// than asserting something unverified.
	ModeSourceNone ModeSource = iota
	// ModeSourceDerived reads the posture from the spawning session, and
	// binds anyway if it cannot: detection needs /proc, so refusing to bind
	// would cost the return path on three of the five platforms shipped.
	ModeSourceDerived
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
	// token is the credential this inbox accepts, generated at bind. It is
	// published only if PublishKey says so, and readable with PeerToken.
	token string

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

// Listen binds an inbox and, if configured, publishes its key file.
func Listen(cfg Config) (*Server, error) {
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
	s := &Server{cfg: cfg, ln: ln, path: path, token: NewToken()}

	if cfg.ModeSource != ModeSourceNone {
		m, err := DetectParentMode()
		if err != nil {
			// Bind anyway, asserting nothing. Worth saying out loud: the
			// symptom otherwise is someone else's message being held, seen
			// from the wrong side of the socket.
			s.logf("asserting no permission mode (%v); frames we originate may be held for approval", err)
		} else {
			s.mode = m
		}
	}

	if cfg.PublishKey {
		k := &Key{PeerToken: s.token}
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

// allocSocketPath picks the first standard directory passing CheckDir, and a
// name carrying our pid — so a peer can attribute the inbox — plus a
// discriminator, so it is not mistaken for a session's own.
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
func (s *Server) PeerToken() string { return s.token }

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
	} else {
		log.Printf("udsmsg: %v", err)
	}
}

func (s *Server) drop(ctx context.Context, p *Peer, line []byte, reason error) {
	if s.cfg.Handler.OnDrop != nil {
		s.cfg.Handler.OnDrop(ctx, p, line, reason)
	} else {
		log.Printf("udsmsg: dropped a frame: %v", reason)
	}
}

func (s *Server) handleConn(ctx context.Context, conn *net.UnixConn) {
	defer conn.Close()

	peer, err := peerCred(conn)
	if err != nil {
		// Identity here is the kernel's answer, so an unidentifiable
		// connection cannot be held to anything — and an empty Peer would
		// hand callers a PID of 0 that reads like a process. Refused unless
		// the caller decides otherwise.
		if !s.cfg.AllowUnidentifiedPeers {
			s.report(fmt.Errorf("refusing a connection whose peer could not be identified "+
				"(set AllowUnidentifiedPeers to accept these): %w", err))
			return
		}
		peer = &Peer{}
		s.report(fmt.Errorf("accepting an unidentified peer: %w", err))
	}
	peer.Addr = s.path

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
				_ = conn.SetReadDeadline(time.Time{}) // deadline served
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
		// The comparison is constant-time, so a wrong token leaks nothing by
		// how long it took to reject.
		switch {
		case subtle.ConstantTimeCompare([]byte(f.Token), []byte(s.token)) == 1:
			peer.Authed = true
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

	h := &s.cfg.Handler
	switch f.Type {
	case TypeUser:
		call(ctx, h.OnUser, h.OnUnknown, peer, f)
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
// It returns complete == false for a trailing partial line, so the caller can
// decide what to do with a final object that arrived without its newline.
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

// logf reports what is neither a dropped frame nor an I/O error, to the
// standard logger. An earlier version wrote to an optional Logger nobody set,
// which made every line here unreachable.
func (s *Server) logf(format string, args ...any) {
	log.Printf("udsmsg: "+format, args...)
}
