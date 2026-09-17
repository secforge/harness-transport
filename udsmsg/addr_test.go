package udsmsg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidAddress(t *testing.T) {
	ok := []string{"uds:/run/user/0/cc-socks/1.sock", "uds:/tmp/cc-socks/2.sock"}
	for _, a := range ok {
		if !ValidAddress(a) {
			t.Errorf("ValidAddress(%q) = false, want true", a)
		}
	}
	bad := []string{"", "uds:", "/run/user/0/x.sock", "other:x", "uds:" + strings.Repeat("x", 201)}
	for _, a := range bad {
		if ValidAddress(a) {
			t.Errorf("ValidAddress(%q) = true, want false", a)
		}
	}
}

func TestParseUDS(t *testing.T) {
	p, ok := ParseUDS("uds:/tmp/cc-socks/9.sock")
	if !ok || p != "/tmp/cc-socks/9.sock" {
		t.Fatalf("ParseUDS = %q, %v", p, ok)
	}
	if _, ok := ParseUDS("other:x"); ok {
		t.Error("a non-uds address should not parse as uds")
	}
}

// Connecting is permissive about the name and strict about the path: a peer
// may call its inbox what it likes, and refusing an unfamiliar name would only
// cost a reply. What must still be refused is anything that is not a plain
// ".sock" leaf, since that is a path, not a name.
func TestValidSocketName(t *testing.T) {
	ok := []string{"5543.sock", "5543-a1b2c3d4.sock", "deadbeef.sock", "relay-2.sock", "inbox.sock"}
	for _, n := range ok {
		if !ValidSocketName(n) {
			t.Errorf("ValidSocketName(%q) = false, want true", n)
		}
	}
	bad := []string{"5543.socket", ".sock", "5543.sock.tmp", "", "a/b.sock", "../escape.sock", "..sock"}
	for _, n := range bad {
		if ValidSocketName(n) {
			t.Errorf("ValidSocketName(%q) = true, want false", n)
		}
	}
}

func TestPIDFromSocketName(t *testing.T) {
	if pid, ok := PIDFromSocketName("5543.sock"); !ok || pid != 5543 {
		t.Errorf("plain pid: got %d, %v", pid, ok)
	}
	if pid, ok := PIDFromSocketName("5543-a1b2c3d4.sock"); !ok || pid != 5543 {
		t.Errorf("discriminated pid: got %d, %v", pid, ok)
	}
	// A name that carries no pid must not be read as one.
	if _, ok := PIDFromSocketName("inbox.sock"); ok {
		t.Error("a name without a pid should not yield one")
	}
}

func TestCheckDir(t *testing.T) {
	base := t.TempDir()
	good := filepath.Join(base, "good")
	if err := os.Mkdir(good, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(good); err != nil {
		t.Errorf("CheckDir(0700 dir) = %v, want nil", err)
	}

	loose := filepath.Join(base, "loose")
	if err := os.Mkdir(loose, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(loose); err == nil {
		t.Error("CheckDir(0755 dir) = nil, want a mode error")
	}

	if err := CheckDir(filepath.Join(base, "absent")); err == nil {
		t.Error("CheckDir(missing) = nil, want an error")
	}

	f := filepath.Join(base, "file")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckDir(f); err == nil {
		t.Error("CheckDir(file) = nil, want an error")
	}
}

// Both address guards are bounded by what the operating system can bind, so a
// socket path at the limit is accepted and one past it is not — in the frame's
// address and in the envelope's alike.
func TestAddressBoundsFollowSunPath(t *testing.T) {
	at := "uds:/" + strings.Repeat("a", MaxSocketPath-1)
	past := at + "a"
	if !ValidAddress(at) {
		t.Errorf("an address with a %d-byte path should be accepted", MaxSocketPath)
	}
	if ValidAddress(past) {
		t.Errorf("an address longer than sun_path should be refused")
	}
	if !fromRe.MatchString(at) || fromRe.MatchString(past) {
		t.Error("the envelope guard should agree with the frame guard on length")
	}
}
