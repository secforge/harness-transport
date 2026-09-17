package udsmsg

import (
	"fmt"
	"os"
	"path/filepath"
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

func TestFindSocketOfAbsentPID(t *testing.T) {
	if _, err := FindSocket(1 << 30); err == nil {
		t.Error("FindSocket of a pid with no socket should fail")
	}
}

// Reaching our own parent should present the credential that session handed
// us, not the one published for strangers. The two do not interchange — the
// child token authenticates to the parent's inbox and nowhere else — and it
// needs no configuration, which the key file does.
// What a receiver then does with the connection is not observable from
// here.
func TestOwnParentIsReachedWithTheChildToken(t *testing.T) {
	// Bound at the canonical <pid>.sock, since that is the name
	// ResolveTarget looks for — an allocated inbox carries a discriminator
	// and is reached by path rather than by pid.
	dir := SocketDirs()[0]
	if CheckDir(dir) != nil {
		t.Skipf("no usable socket directory at %s", dir)
	}
	srv, err := Listen(Config{
		Path:       filepath.Join(dir, fmt.Sprintf("%d.sock", os.Getpid())),
		PublishKey: true,
	})
	if err != nil {
		t.Skipf("cannot bind an inbox here: %v", err)
	}
	defer srv.Close()

	t.Setenv(EnvMessagingSocket, srv.Path())
	t.Setenv(EnvMessagingToken, "the-inherited-child-token")

	got, err := ResolveTarget(os.Getpid())
	if err != nil {
		t.Fatalf("ResolveTarget: %v", err)
	}
	if got.Token != "the-inherited-child-token" {
		t.Errorf("token = %q; the inherited child token should win over the published peer token", got.Token)
	}

	// A different session is necessarily a peer, and the child token
	// authenticates only to the parent — so it must not leak there.
	t.Setenv(EnvMessagingSocket, "/run/user/0/cc-socks/999999.sock")
	got, err = ResolveTarget(os.Getpid())
	if err != nil {
		t.Fatalf("ResolveTarget: %v", err)
	}
	if got.Token == "the-inherited-child-token" {
		t.Error("the child token was used for a target that is not our parent")
	}
	if got.Token != srv.PeerToken() {
		t.Errorf("token = %q, want the published peer token", got.Token)
	}
}
