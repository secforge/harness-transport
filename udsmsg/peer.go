package udsmsg

import (
	"errors"
)

// Peer is the verified identity of a connected client, derived from the
// socket's credentials independently of any token it presented.
type Peer struct {
	// PID, UID and GID come from the kernel, so no client can forge them.
	PID int32
	UID uint32
	GID uint32
	// ProcStart is the peer's start time, defeating pid reuse. Empty if the
	// process had already exited.
	ProcStart string
	// Authed reports that a valid token was presented.
	Authed bool
	Addr   string
	// Identified reports that the kernel answered. When false the PID of 0 is
	// an absence, not a process, and comparing it would be meaningless.
	Identified bool
}

func (p *Peer) Authenticated() bool { return p.Authed }

// ErrPeerCredsUnavailable is returned where the system offers no way to ask
// who is on the other end. A distinct error rather than a zero Peer, because
// a PID of 0 reads as an identity while this says none was established.
var ErrPeerCredsUnavailable = errors.New("peer credentials are not available on this platform")
