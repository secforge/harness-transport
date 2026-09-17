//go:build !linux && !darwin

package udsmsg

import "net"

// peerCred has no implementation here: Windows has no equivalent for AF_UNIX
// sockets, and uses named pipes this package does not implement. It fails
// rather than returning an empty Peer, so an absent identity is a decision
// the caller makes rather than a zero value that reads like an answer.
func peerCred(net.Conn) (*Peer, error) { return nil, ErrPeerCredsUnavailable }
