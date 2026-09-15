package udsmsg

import (
	"fmt"
	"net"
	"syscall"
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
	// PID, UID and GID come from SO_PEERCRED and cannot be forged by the
	// client.
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
}

// Authenticated reports whether the connection presented a valid token.
func (p *Peer) Authenticated() bool { return p.Auth != AuthNone }

// peerCred reads SO_PEERCRED from a unix connection.
func peerCred(c net.Conn) (*Peer, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	if credErr != nil {
		return nil, credErr
	}
	p := &Peer{PID: cred.Pid, UID: cred.Uid, GID: cred.Gid}
	if ps, err := ProcStart(int(cred.Pid)); err == nil {
		p.ProcStart = ps
	}
	return p, nil
}
