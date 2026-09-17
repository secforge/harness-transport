package udsmsg

import (
	"strings"
	"testing"
)

// An entry describes the process that published it, and the fields saying
// what that process is come from the caller. Nothing is defaulted: a record
// that says "interactive" when it is not is read as a session by everything
// that lists the registry.
func TestEntryRecordsTheKindTheCallerGave(t *testing.T) {
	e, err := NewSessionEntry("/run/user/0/cc-socks/4242-a1b2c3d4.sock", "example · inbox", "relay", "daemon")
	if err != nil {
		t.Fatal(err)
	}
	if e.Name != "example · inbox" {
		t.Errorf("name = %q, want the caller's verbatim", e.Name)
	}
	if e.Kind != "relay" || e.Entrypoint != "daemon" {
		t.Errorf("kind/entrypoint = %q/%q, want what the caller passed", e.Kind, e.Entrypoint)
	}
	if e.PID == 0 || e.ProcStart == "" || e.MessagingSocketPath == "" {
		t.Errorf("entry is missing what this package does know: %+v", e)
	}
}

// A name that cannot be displayed is refused rather than repaired: a caller
// that passed something unusable should hear so, not publish under a name it
// did not choose. No length is enforced, since none was observed.
func TestEntryNameIsRefusedRatherThanRepaired(t *testing.T) {
	const sock = "/run/user/0/cc-socks/4242-a1b2c3d4.sock"
	for _, bad := range []string{"", "   ", "two\nlines", "bell\aname"} {
		if _, err := NewSessionEntry(sock, bad, "relay", "daemon"); err == nil {
			t.Errorf("NewSessionEntry(%q) was accepted; it cannot be displayed as given", bad)
		}
	}
	long := strings.Repeat("n", 5000)
	if e, err := NewSessionEntry(sock, long, "relay", "daemon"); err != nil {
		t.Errorf("a long name should be accepted, no limit was ever observed: %v", err)
	} else if e.Name != long {
		t.Error("an accepted name must be recorded as given")
	}
}
