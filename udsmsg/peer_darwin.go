package udsmsg

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// peerCred reads the peer's credentials on macOS, which needs two calls where
// Linux needs one: LOCAL_PEERCRED yields a Xucred carrying the uid and the
// group list but NO pid, and LOCAL_PEERPID yields the pid on its own.
//
// Both are asked for, and the pid matters most here — identity in this
// protocol is a pid plus a start time, so a uid alone would authenticate a
// user rather than a process.
func peerCred(c net.Conn) (*Peer, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return nil, fmt.Errorf("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, err
	}
	var (
		cred    *unix.Xucred
		pid     int
		credErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if credErr != nil {
			return
		}
		pid, credErr = unix.GetsockoptInt(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERPID)
	}); err != nil {
		return nil, err
	}
	if credErr != nil {
		return nil, credErr
	}
	p := &Peer{PID: int32(pid), UID: cred.Uid, Identified: true}
	if len(cred.Groups) > 0 {
		p.GID = cred.Groups[0]
	}
	if ps, err := ProcStart(pid); err == nil {
		p.ProcStart = ps
	}
	return p, nil
}
