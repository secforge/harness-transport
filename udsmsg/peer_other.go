//go:build !linux && !darwin

package udsmsg

import "net"

// peerCred has no implementation here. Windows has no equivalent of
// SO_PEERCRED or LOCAL_PEERCRED for AF_UNIX sockets, and the harness does not
// use unix sockets there anyway — it uses named pipes, which this package
// does not implement.
//
// It fails rather than returning an empty Peer, so that a caller relying on
// verified identity has to decide what an absent one means instead of
// inheriting a zero value that reads like an answer.
func peerCred(net.Conn) (*Peer, error) { return nil, ErrPeerCredsUnavailable }
