package main

import (
	"strings"
	"testing"

	"github.com/secforge/harness-transport/udsmsg"
)

func TestDefaultNameNamesTheDirectory(t *testing.T) {
	if got := defaultName(1); !strings.HasPrefix(got, "claude-send") {
		t.Errorf("defaultName = %q, want it to identify claude-send", got)
	}
}

func quiet(string, ...any) {}

// Our inbox sits in a directory every process of this uid can reach, so the
// answer must be told apart from anything else that turns up.
func TestAccepterHearsOnlyTheAddressedProcess(t *testing.T) {
	accept := accepter(udsmsg.Target{PID: 4242, SocketPath: "/run/user/0/cc-socks/4242.sock"}, false, quiet)
	if !accept(&udsmsg.Peer{PID: 4242, Identified: true}) {
		t.Error("the addressed process should be heard")
	}
	if accept(&udsmsg.Peer{PID: 99, Identified: true}) {
		t.Error("a stranger should not be mistaken for the reply")
	}
}

// --to-socket carries no pid of its own; the socket name usually does.
func TestAccepterTakesThePIDFromTheSocketName(t *testing.T) {
	accept := accepter(udsmsg.Target{SocketPath: "/run/user/0/cc-socks/4242-a1b2c3d4.sock"}, false, quiet)
	if !accept(&udsmsg.Peer{PID: 4242, Identified: true}) {
		t.Error("the pid in the socket name should be used")
	}
	if accept(&udsmsg.Peer{PID: 99, Identified: true}) {
		t.Error("a stranger should not be mistaken for the reply")
	}
}

// An opaque 16-hex socket name encodes no pid, so there is nothing to check
// and nothing may be silently dropped.
func TestAccepterHearsEveryoneWhenThePIDIsUnknowable(t *testing.T) {
	accept := accepter(udsmsg.Target{SocketPath: "/run/user/0/cc-socks/deadbeefdeadbeef.sock"}, false, quiet)
	if !accept(&udsmsg.Peer{PID: 99, Identified: true}) {
		t.Error("with no pid to compare, frames must still be delivered")
	}
}

func TestAnySenderDisablesTheFilter(t *testing.T) {
	accept := accepter(udsmsg.Target{PID: 4242}, true, quiet)
	if !accept(&udsmsg.Peer{PID: 99, Identified: true}) {
		t.Error("--any-sender should hear everyone")
	}
}

func TestPlural(t *testing.T) {
	if plural(1) != "y" || plural(0) != "ies" || plural(2) != "ies" {
		t.Error("reply/replies suffix is wrong")
	}
}

// A peer the kernel would not identify is heard rather than silently
// rejected: comparing a pid we do not have against one we want would refuse
// every frame on a platform that answers no such question, and the caller
// would see only silence.
func TestAccepterHearsAnUnidentifiedPeer(t *testing.T) {
	accept := accepter(udsmsg.Target{PID: 4242}, false, quiet)
	if !accept(&udsmsg.Peer{}) {
		t.Error("an unidentified peer should be heard, with the uncertainty reported")
	}
}
