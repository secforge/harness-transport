package udsmsg

import (
	"errors"
)

// AuthIdentity is the identity a connection established by presenting a
// token. Both peer and child tokens are accepted.
type AuthIdentity string

const (
	AuthNone  AuthIdentity = ""
	AuthPeer  AuthIdentity = "peer"
	AuthChild AuthIdentity = "child"
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
	// Auth is the identity established by the auth frame, if any.
	Auth AuthIdentity
	// SelfSent marks a message that appears to originate from the receiver
	// itself.
	SelfSent bool
	// Addr is the local socket the peer connected to.
	Addr string
	// Identified reports that the kernel actually answered. A Peer with
	// Identified false carries no identity at all — its PID of 0 is an
	// absence, not a process — and anything comparing pids must say so
	// rather than letting 0 match or fail on its own.
	Identified bool
}

// Authenticated reports whether the connection presented a valid token.
func (p *Peer) Authenticated() bool { return p.Auth != AuthNone }

// ErrPeerCredsUnavailable is returned by peerCred where the operating system
// exposes no way to ask the kernel who is on the other end of a socket.
//
// It is a distinct error rather than a zero-valued Peer because the two mean
// opposite things. A Peer whose PID is 0 reads as an identity; this says no
// identity was established, so a caller enforcing anything on the strength of
// one has to decide what to do rather than carry on holding nothing.
var ErrPeerCredsUnavailable = errors.New("peer credentials are not available on this platform")
