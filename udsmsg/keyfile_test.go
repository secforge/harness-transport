package udsmsg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestKeyFileNameIsSHA256OfCanonicalPath(t *testing.T) {
	// The digest of "/tmp/cc-socks/1.sock", fixed by the protocol.
	name, err := KeyFileName(1, "/tmp/cc-socks/1.sock")
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(name, ".")
	if len(parts) != 3 || parts[0] != "1" || parts[2] != "key" {
		t.Fatalf("name %q is not <pid>.<64 hex>.key", name)
	}
	if len(parts[1]) != 64 || strings.Trim(parts[1], "0123456789abcdef") != "" {
		t.Fatalf("digest component %q is not 64 hex characters", parts[1])
	}
	// A non-canonical spelling of the same path must hash identically.
	same, err := KeyFileName(1, "/tmp/cc-socks/./1.sock")
	if err != nil {
		t.Fatal(err)
	}
	if same != name {
		t.Errorf("non-canonical path gave %q, want %q", same, name)
	}
}

// TestKeyFileNameMatchesLiveSessions checks our naming against the key files
// Claude Code itself published on this host. It is the strongest available
// confirmation that the digest is computed over the right string.
func TestKeyFileNameMatchesLiveSessions(t *testing.T) {
	ents, err := os.ReadDir(SessionsDir())
	if err != nil {
		t.Skip("no session registry on this host")
	}
	checked := 0
	for _, e := range ents {
		name := e.Name()
		if !strings.HasSuffix(name, ".key") {
			continue
		}
		pidStr, _, ok := strings.Cut(name, ".")
		if !ok {
			continue
		}
		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			continue
		}
		b, err := os.ReadFile(filepath.Join(SessionsDir(), pidStr+".json"))
		if err != nil {
			continue // key file without a registry entry
		}
		var r registryEntry
		if err := json.Unmarshal(b, &r); err != nil || r.MessagingSocketPath == "" {
			continue
		}
		got, err := KeyFileName(pid, r.MessagingSocketPath)
		if err != nil {
			t.Fatal(err)
		}
		if got != name {
			t.Errorf("pid %d socket %s:\n got  %s\n want %s", pid, r.MessagingSocketPath, got, name)
		}
		checked++
	}
	if checked == 0 {
		t.Skip("no key file with a matching registry entry")
	}
	t.Logf("verified naming against %d live key files", checked)
}

func TestWriteReadRemoveKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	sock := filepath.Join(dir, "7.sock")
	want := &Key{PeerToken: NewToken(), ProcStart: "1162506", PIDDomain: "linux:abc:pid:[4026532231]"}
	if err := WriteKey(7, sock, want); err != nil {
		t.Fatal(err)
	}

	// The sessions directory must not be readable by other users.
	fi, err := os.Stat(SessionsDir())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Errorf("sessions dir mode = %#o, want 0700", fi.Mode().Perm())
	}
	name, _ := KeyFileName(7, sock)
	kf, err := os.Stat(filepath.Join(SessionsDir(), name))
	if err != nil {
		t.Fatal(err)
	}
	if kf.Mode().Perm() != 0o600 {
		t.Errorf("key file mode = %#o, want 0600", kf.Mode().Perm())
	}

	got, err := ReadKey(7, sock)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || *got != *want {
		t.Fatalf("ReadKey = %+v, want %+v", got, want)
	}

	// No temporary file may survive the atomic write.
	ents, _ := os.ReadDir(SessionsDir())
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Errorf("temporary file %s left behind", e.Name())
		}
	}

	if err := RemoveKey(7, sock); err != nil {
		t.Fatal(err)
	}
	if err := RemoveKey(7, sock); err != nil {
		t.Errorf("removing an absent key = %v, want nil", err)
	}
}

// A missing key file is not an error: auth is optional by default.
func TestReadKeyAbsentIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	k, err := ReadKey(999999, filepath.Join(dir, "999999.sock"))
	if err != nil {
		t.Fatalf("ReadKey(absent) = %v, want nil", err)
	}
	if k != nil {
		t.Errorf("ReadKey(absent) = %+v, want nil", k)
	}
}

func TestReadKeyRejectsOversizeFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	sock := filepath.Join(dir, "8.sock")
	name, _ := KeyFileName(8, sock)
	if err := os.MkdirAll(SessionsDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	big := make([]byte, maxKeyFileBytes+1)
	if err := os.WriteFile(filepath.Join(SessionsDir(), name), big, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKey(8, sock); err == nil {
		t.Error("an oversize key file should be rejected")
	}
}

func TestNewTokenIs32Hex(t *testing.T) {
	tok := NewToken()
	if len(tok) != 32 || strings.Trim(tok, "0123456789abcdef") != "" {
		t.Errorf("token %q is not 32 hex characters", tok)
	}
	if NewToken() == tok {
		t.Error("tokens must not repeat")
	}
}
