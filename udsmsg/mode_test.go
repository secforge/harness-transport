package udsmsg

import (
	"os"
	"testing"
)

func TestModeFromCmdline(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cmdline string
		want    Mode
	}{
		{"plain remote-control session", "claude --remote-control --name build --resume abc", ModePrompting},
		{"skip-permissions flag", "claude --dangerously-skip-permissions", ModeBypass},
		{"permission-mode separate arg", "claude --permission-mode bypassPermissions", ModeBypass},
		{"permission-mode joined", "claude --permission-mode=bypassPermissions", ModeBypass},
		{"an explicitly prompting session", "claude --permission-mode prompting", ModePrompting},
		{"nothing at all", "", ModePrompting},
	} {
		if got := modeFromCmdline(tc.cmdline); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The posture must never be invented, so the failure to establish one is
// reported as a failure and not as a default that happens to clear the gate.
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
