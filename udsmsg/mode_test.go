package udsmsg

import (
	"os"
	"testing"
)

// The posture must never be invented, so the failure to establish one is
// reported as a failure and not as a default that happens to clear a gate.
// Every path that cannot see a live spawning session must say so.
func TestDetectParentModeRefusesWithoutAParent(t *testing.T) {
	t.Setenv(EnvMessagingSocket, "")
	if m, err := DetectParentMode(); err == nil {
		t.Fatalf("got mode %q with no parent socket, want an error", m)
	}
	t.Setenv(EnvMessagingSocket, "/run/user/0/cc-socks/deadbeefdeadbeef.sock")
	if m, err := DetectParentMode(); err == nil {
		t.Fatalf("got mode %q from a socket name carrying no pid, want an error", m)
	}
	t.Setenv(EnvMessagingSocket, "/run/user/0/cc-socks/4194303.sock")
	if _, err := DetectParentMode(); err == nil && os.Getpid() != 4194303 {
		t.Fatal("got a mode for a pid that is not running, want an error")
	}
}
