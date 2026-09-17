package udsmsg

import "testing"

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
