// Command claude-send sends a message to another Claude Code session on this
// machine over the uds-messaging protocol, and waits for an answer.
//
// Because the protocol has no request/response, waiting for an answer means
// running an inbox of our own: we bind a socket, name it as the reply address,
// and block until the peer sends a message back to it.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/secforge/harness-transport/udsmsg"
)

// Exit codes, so a script can tell the outcomes apart.
const (
	exitOK       = 0 // answer received, or the requested wait completed
	exitError    = 1 // setup or protocol failure
	exitNoReply  = 3 // the peer went idle without answering
	exitTimeout  = 4 // nothing conclusive within --timeout
	exitRefused  = 5 // denied, expired, refused or dropped
	exitNoTarget = 6 // no such session
)

// isTerminal reports whether f is a terminal, so that a message can be read
// from a pipe without a flag while an interactive run still shows usage.
func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// accepter decides whether a frame that reached our inbox came from the
// process we addressed. Identity is the peer's SO_PEERCRED pid, which no
// sender can forge; a frame's `from` is merely asserted. A socket name
// carrying no pid leaves nothing to compare, and the progress line says so
// rather than implying a check that did not happen.
func accepter(target udsmsg.Target, anySender bool, progress func(string, ...any)) func(*udsmsg.Peer) bool {
	if anySender {
		return func(*udsmsg.Peer) bool { return true }
	}
	want := target.PID
	if want == 0 {
		want, _ = udsmsg.PIDFromSocketName(filepath.Base(target.SocketPath))
	}
	if want == 0 {
		progress("target pid is unknown, so any sender will be heard")
		return func(*udsmsg.Peer) bool { return true }
	}
	var warned bool
	return func(p *udsmsg.Peer) bool {
		if !p.Identified {
			// No identity at all, rather than a pid that happens not to
			// match. Comparing against it would silently reject everything
			// on a platform where the kernel answers no such question.
			if !warned {
				warned = true
				progress("frames are arriving from a peer the kernel will not identify on this " +
					"platform, so they cannot be told from anyone else's: hearing them anyway")
			}
			return true
		}
		if int(p.PID) == want {
			return true
		}
		if !warned {
			warned = true
			progress("ignoring frames from pid %d: waiting for pid %d (use --any-sender to hear everyone)", p.PID, want)
		}
		return false
	}
}

// defaultName identifies this sender when no --name or --announce is given.
func defaultName(pid int) string {
	cwd, err := os.Getwd()
	if err != nil {
		return "claude-send"
	}
	return fmt.Sprintf("claude-send in %s", filepath.Base(cwd))
}

type options struct {
	to         int
	toSocket   string
	wait       string
	timeout    time.Duration
	noAuth     bool
	noHint     bool
	jsonOut    bool
	quiet      bool
	anySender  bool
	name       string
	announce   string
	publishKey bool
}

func main() {
	os.Exit(run())
}

func run() int {
	var o options
	flag.IntVar(&o.to, "to", 0, "pid of the target session")
	flag.StringVar(&o.toSocket, "to-socket", "", "socket path of the target inbox, instead of --to")
	flag.StringVar(&o.wait, "wait", "reply", "what to wait for: reply, replies, none")
	flag.DurationVar(&o.timeout, "timeout", 5*time.Minute, "give up after this long; with --wait replies, how long to keep listening")
	flag.BoolVar(&o.anySender, "any-sender", false, "accept frames from any process, not only the addressed one")
	flag.BoolVar(&o.noAuth, "no-auth", false, "dial without a token even if a key file exists; a receiver that requires authentication closes such a connection without a reason")
	flag.BoolVar(&o.noHint, "no-hint", false, "send the bare text, without the cross-session attribution wrapper")
	flag.StringVar(&o.name, "name", "", "how to identify ourselves in the message (default: claude-send in <dir>)")
	flag.BoolVar(&o.jsonOut, "json", false, "print every received frame as JSON")
	flag.BoolVar(&o.quiet, "quiet", false, "suppress progress on stderr")
	flag.StringVar(&o.announce, "announce", "", "publish a session registry entry under this name while waiting, so peers can attribute us")
	flag.BoolVar(&o.publishKey, "publish-key", false, "publish a key file for our inbox, so peers can authenticate to us")
	flag.Usage = usage
	flag.Parse()

	text := strings.Join(flag.Args(), " ")
	if text == "-" || (text == "" && !isTerminal(os.Stdin)) {
		// A single argv string is capped at MAX_ARG_STRLEN (128 KiB on
		// Linux), well under what this protocol carries, so a message near
		// the wire limit can only arrive on stdin.
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "claude-send: read stdin: %v\n", err)
			return exitError
		}
		text = strings.TrimRight(string(b), "\n")
	}
	if (o.to == 0 && o.toSocket == "") || text == "" {
		usage()
		return exitError
	}
	if o.to != 0 && o.toSocket != "" {
		fmt.Fprintln(os.Stderr, "claude-send: give --to or --to-socket, not both")
		return exitError
	}
	switch o.wait {
	case "reply", "replies", "none":
	default:
		fmt.Fprintf(os.Stderr, "claude-send: unknown --wait %q\n", o.wait)
		return exitError
	}
	return send(o, text)
}

// resolve turns --to or --to-socket into a destination, reading the token
// published for that socket when there is one.
func resolve(o options) (udsmsg.Target, error) {
	if o.toSocket != "" {
		t := udsmsg.Target{SocketPath: o.toSocket}
		if pid, ok := udsmsg.PIDFromSocketName(filepath.Base(o.toSocket)); ok {
			t.PID = pid
			k, err := udsmsg.ReadKey(pid, o.toSocket)
			if err != nil {
				return t, err
			}
			if k != nil {
				t.Token, t.ProcStart = k.PeerToken, k.ProcStart
			}
		}
		return t, nil
	}
	return udsmsg.ResolveTarget(o.to)
}

func usage() {
	fmt.Fprint(os.Stderr, `claude-send — message another Claude Code session on this machine

  claude-send --to <pid> [flags] <message text>
  claude-send --to-socket <path> [flags] <message text>

`)
	flag.PrintDefaults()
}

func send(o options, text string) int {
	target, err := resolve(o)
	if err != nil {
		fmt.Fprintf(os.Stderr, "claude-send: %v\n", err)
		return exitNoTarget
	}
	if o.noAuth {
		// Deliberate, and it has to be said twice — once by the flag and
		// once to the library, which otherwise refuses a tokenless dial.
		target.Token, target.Unauthenticated = "", true
	}
	// A published start time lets us refuse a recycled pid before we speak.
	if target.PID != 0 && target.ProcStart != "" && !udsmsg.Alive(target.PID, target.ProcStart) {
		fmt.Fprintf(os.Stderr, "claude-send: pid %d is not the process that published the socket\n", target.PID)
		return exitNoTarget
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()

	// Our own posture is derived, never stated: there is no flag for it,
	// because a flag is a way to claim one. Undeterminable means we assert
	// nothing and accept the hold.
	mode, err := udsmsg.DetectParentMode()
	if err != nil {
		mode = ""
	}
	progress := func(format string, a ...any) {
		if !o.quiet {
			fmt.Fprintf(os.Stderr, format+"\n", a...)
		}
	}

	// An inbox of our own is what makes a reply possible at all: without it
	// there is no address to put in `from`.
	replies := make(chan *udsmsg.Frame, 16)
	var srv *udsmsg.Server
	var entry *udsmsg.SessionEntry
	if o.wait != "none" {
		// The inbox is a socket in a directory every process of this uid can
		// reach, so anyone could send us a frame and be mistaken for the
		// answer. SO_PEERCRED cannot be forged, so unless --any-sender is
		// given we hear only the process we asked.
		accept := accepter(target, o.anySender, progress)
		deliver := func(p *udsmsg.Peer, f *udsmsg.Frame) {
			if accept(p) {
				replies <- f
			}
		}
		h := udsmsg.Handler{
			OnUser:  func(_ context.Context, p *udsmsg.Peer, f *udsmsg.Frame) { deliver(p, f) },
			OnError: func(err error) { progress("claude-send: inbox: %v", err) },
		}
		srv, err = udsmsg.Listen(udsmsg.Config{Handler: h, PublishKey: o.publishKey})
		if err != nil {
			fmt.Fprintf(os.Stderr, "claude-send: bind inbox: %v\n", err)
			return exitError
		}
		defer srv.Close()
		srv.Start(ctx)
		progress("inbox %s", srv.Path())

		if o.announce != "" {
			// What this is: a command-line tool holding an inbox, not a
			// session. Saying "interactive" would claim to be one.
			entry, err = udsmsg.NewSessionEntry(srv.Path(), o.announce, "cli", "cli")
			if err != nil {
				fmt.Fprintf(os.Stderr, "claude-send: build registry entry: %v\n", err)
				return exitError
			}
			if err := udsmsg.PublishSession(entry); err != nil {
				fmt.Fprintf(os.Stderr, "claude-send: publish registry entry: %v\n", err)
				return exitError
			}
			defer udsmsg.UnpublishSession(entry.PID)
			progress("announced as %q (pid %d, session %s)", entry.Name, entry.PID, entry.SessionID)
		}
	}

	from := ""
	if srv != nil {
		from = srv.Addr()
	}
	var attribution *udsmsg.CrossSession
	if !o.noHint {
		name := o.name
		if name == "" {
			name = o.announce
		}
		if name == "" {
			name = defaultName(os.Getpid())
		}
		// A session that is waiting says so in the body: the wrapper carries
		// identity, not intent, and a peer that does not know we are waiting
		// answers in its own transcript and leaves us on the timeout.
		switch o.wait {
		case "reply":
			text += "\n\n[The sender is blocked waiting for a reply to this address.]"
		case "replies":
			text += fmt.Sprintf("\n\n[The sender is collecting replies at this address for the next %s; more than one is welcome.]", o.timeout)
		}
		attribution = &udsmsg.CrossSession{From: from, Name: name, Mode: mode}
	}

	// Build the payload before connecting: a connection that has not
	// completed a line within 30 s is closed.
	c, err := udsmsg.Dial(ctx, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "claude-send: %v\n", err)
		return exitError
	}
	defer c.Close()

	u := udsmsg.User{Text: text, From: from, FromMode: mode, Attribution: attribution}
	msgID, err := c.SendUser(u)
	if err != nil {
		fmt.Fprintf(os.Stderr, "claude-send: send: %v\n", err)
		return exitError
	}
	authNote := "unauthenticated"
	if target.Token != "" {
		authNote = "authenticated"
	}
	progress("sent %s to %s (%s)", msgID, target.SocketPath, authNote)

	if o.wait == "none" {
		return exitOK
	}
	return await(ctx, o, replies, msgID, progress)
}

// await blocks on the inbox until the wait condition is met. --wait reply
// returns on the first answer; --wait replies stays for the whole timeout,
// printing each as it arrives, since the second thing a peer says is often
// the useful one. A window that produced answers exits 0.
func await(ctx context.Context, o options, replies <-chan *udsmsg.Frame, msgID string,
	progress func(string, ...any)) int {

	collecting := o.wait == "replies"
	received := 0

	for {
		select {
		case <-ctx.Done():
			if collecting {
				progress("collected %d repl%s in %s", received, plural(received), o.timeout)
				if received > 0 {
					return exitOK
				}
				return exitTimeout
			}
			progress("timed out after %s", o.timeout)
			return exitTimeout

		case f := <-replies:
			if o.jsonOut {
				fmt.Println(string(f.Raw))
			}
			if f.Type != udsmsg.TypeUser {
				continue
			}
			received++
			if !o.jsonOut {
				// A peer answers with the same attributed envelope we
				// send, which is markup for a harness, not for a script.
				cs, body, wrapped := udsmsg.Unwrap(f.Text())
				if wrapped && cs.Name != "" {
					progress("reply from %s", cs.Name)
				}
				fmt.Println(body)
			}
			if collecting {
				continue // more may follow within the window
			}
			return exitOK
		}
	}
}

// plural is the suffix for a count of replies.
func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}
