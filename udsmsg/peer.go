package udsmsg

import (
	"errors"
)

// Peer is the verified identity of a connected client, derived from the
// socket's credentials independently of any token it presented.
type Peer struct {
	// PID, UID and GID come from the kernel, not from anything the client
	// sent, so they cannot be forged. Where the platform exposes no such
	// call, peerCred fails with ErrPeerCredsUnavailable rather than
	// returning a Peer that looks identified and is not.
	PID int32
	UID uint32
	GID uint32
	// ProcStart is the peer's start time, read from /proc at accept time to
	// defeat pid reuse. Empty if the process had already exited.
	ProcStart string
	// Authed reports that the connection presented a valid token. Which of
	// the accepted tokens it was is not recorded: both authenticate, and
	// nothing observed distinguishes what follows.
	Authed bool
	// Addr is the local socket the peer connected to.
	Addr string
	// Identified reports that the kernel actually answered. A Peer with
	// Identified false carries no identity at all — its PID of 0 is an
	// absence, not a process — and anything comparing pids must say so
	// rather than letting 0 match or fail on its own.
	Identified bool
}

// Authenticated reports whether the connection presented a valid token.
func (p *Peer) Authenticated() bool { return p.Authed }

// ErrPeerCredsUnavailable is returned where the system offers no way to ask
// who is on the other end. A distinct error rather than a zero Peer, because
// a PID of 0 reads as an identity while this says none was established.
var ErrPeerCredsUnavailable = errors.New("peer credentials are not available on this platform")
