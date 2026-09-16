package udsmsg

import (
	"fmt"
	"net"
	"syscall"
)

// peerCred reads SO_PEERCRED, which returns pid, uid and gid in one struct.
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
	p := &Peer{PID: cred.Pid, UID: cred.Uid, GID: cred.Gid, Identified: true}
	if ps, err := ProcStart(int(cred.Pid)); err == nil {
		p.ProcStart = ps
	}
	return p, nil
}
