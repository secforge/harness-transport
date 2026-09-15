package udsmsg

import (
	"os"
	"strconv"
	"testing"
)

func TestProcStartOfSelf(t *testing.T) {
	got, err := ProcStart(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strconv.ParseUint(got, 10, 64); err != nil {
		t.Fatalf("ProcStart = %q, want a number of clock ticks", got)
	}
	// Stable across calls: it is a start time, not a clock reading.
	again, err := ProcStart(os.Getpid())
	if err != nil || again != got {
		t.Errorf("ProcStart changed between calls: %q then %q", got, again)
	}
}

// A process name containing spaces and parentheses must not shift the field
// offsets; the parser counts from the last ')'.
func TestProcStartOfInit(t *testing.T) {
	if _, err := os.Stat("/proc/1/stat"); err != nil {
		t.Skip("no /proc/1")
	}
	if _, err := ProcStart(1); err != nil {
		t.Errorf("ProcStart(1) = %v", err)
	}
}

func TestProcStartOfAbsentPID(t *testing.T) {
	if _, err := ProcStart(1 << 30); err == nil {
		t.Error("ProcStart of a non-existent pid should fail")
	}
}

func TestAlive(t *testing.T) {
	self := os.Getpid()
	ps, err := ProcStart(self)
	if err != nil {
		t.Fatal(err)
	}
	if !Alive(self, ps) {
		t.Error("our own process should be alive")
	}
	if !Alive(self, "") {
		t.Error("an empty start time should check existence only")
	}
	// A mismatched start time is exactly the pid-reuse case.
	if Alive(self, "999999999") {
		t.Error("a mismatched start time should not count as alive")
	}
	if Alive(1<<30, "") {
		t.Error("a non-existent pid should not count as alive")
	}
}

func TestPIDDomainShape(t *testing.T) {
	d, err := PIDDomain(os.Getpid())
	if err != nil {
		t.Skipf("pid domain unavailable: %v", err)
	}
	if len(d) < len("linux::pid:[]") || d[:6] != "linux:" {
		t.Errorf("pid domain %q is not linux:<machine-id>:pid:[<inode>]", d)
	}
}

func TestSocketDirsArePreferenceOrdered(t *testing.T) {
	dirs := SocketDirs()
	if len(dirs) == 0 {
		t.Fatal("no socket directories")
	}
	seen := map[string]bool{}
	for _, d := range dirs {
		if seen[d] {
			t.Errorf("duplicate directory %s", d)
		}
		seen[d] = true
	}
}

// Discover must survive whatever is on the host, and must never report a
// session as live unless /proc agrees.
func TestDiscoverIsConsistent(t *testing.T) {
	sessions, err := Discover()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sessions {
		if s.PID <= 0 {
			t.Errorf("session with pid %d", s.PID)
		}
		if s.Live && !Alive(s.PID, s.ProcStart) {
			t.Errorf("pid %d reported live but /proc disagrees", s.PID)
		}
		if s.HasKey && s.SocketPath == "" {
			t.Errorf("pid %d has a key but no socket", s.PID)
		}
	}
	t.Logf("discovered %d sessions", len(sessions))
}

func TestFindSocketOfAbsentPID(t *testing.T) {
	if _, err := FindSocket(1 << 30); err == nil {
		t.Error("FindSocket of a pid with no socket should fail")
	}
}

func TestTargetFromEnv(t *testing.T) {
	t.Setenv("CLAUDE_CODE_MESSAGING_SOCKET", "/run/user/0/cc-socks/4242.sock")
	t.Setenv("CLAUDE_CODE_MESSAGING_TOKEN", "abc123")
	got, ok := TargetFromEnv()
	if !ok {
		t.Fatal("TargetFromEnv = false, want true")
	}
	if got.PID != 4242 || got.Token != "abc123" {
		t.Errorf("TargetFromEnv = %+v", got)
	}

	t.Setenv("CLAUDE_CODE_MESSAGING_SOCKET", "")
	if _, ok := TargetFromEnv(); ok {
		t.Error("TargetFromEnv should report false without a socket path")
	}
}
