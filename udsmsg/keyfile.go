package udsmsg

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// maxKeyFileBytes bounds what ReadKey will take from a file whose size it does
// not control. A key file holds three short strings; anything larger is not
// one, and reading it would be the only unbounded read in this package.
const maxKeyFileBytes = 4096

// Key is the content of a session's published key file. procStart and
// pidDomain bind the token to one specific live process, so a recycled pid
// cannot impersonate the session that published it.
type Key struct {
	PeerToken string `json:"peerToken"`
	ProcStart string `json:"procStart"`
	PIDDomain string `json:"pidDomain"`
}

// sessionsDir is the directory holding the session registry and key files.
func sessionsDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join("/root", ".claude", "sessions")
	}
	return filepath.Join(home, ".claude", "sessions")
}

// keyFileName returns the key file name for a session: the pid, then the
// sha256 of the canonical socket path, which binds a key to one socket.
func keyFileName(pid int, socketPath string) (string, error) {
	canon, err := filepath.EvalSymlinks(socketPath)
	if err != nil {
		// A socket that has gone away still has a well-defined canonical
		// name; fall back to lexical resolution.
		canon = filepath.Clean(socketPath)
	}
	abs, err := filepath.Abs(canon)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(abs))
	return fmt.Sprintf("%d.%s.key", pid, hex.EncodeToString(sum[:])), nil
}

// ReadKey loads the key a session published for exactly this socket. A
// missing key file is not an error in the default configuration, where auth
// is optional: it returns (nil, nil).
func ReadKey(pid int, socketPath string) (*Key, error) {
	name, err := keyFileName(pid, socketPath)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(sessionsDir(), name)
	fi, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if fi.Size() > maxKeyFileBytes {
		return nil, fmt.Errorf("%s is %d bytes, over the %d byte cap", path, fi.Size(), maxKeyFileBytes)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var k Key
	if err := json.Unmarshal(b, &k); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &k, nil
}

// writeKey publishes a key file atomically, through a temporary name that is
// renamed into place so a reader never sees a partial file.
func writeKey(pid int, socketPath string, k *Key) error {
	name, err := keyFileName(pid, socketPath)
	if err != nil {
		return err
	}
	dir := sessionsDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(k)
	if err != nil {
		return err
	}
	if len(b) > maxKeyFileBytes {
		return fmt.Errorf("key file would be %d bytes, over the %d byte cap", len(b), maxKeyFileBytes)
	}
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	tmp := filepath.Join(dir, fmt.Sprintf("%s.tmp.%s", name, hex.EncodeToString(suffix[:])))
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// removeKey deletes a published key file. A missing file is not an error.
func removeKey(pid int, socketPath string) error {
	name, err := keyFileName(pid, socketPath)
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(sessionsDir(), name)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// newToken returns a fresh 128-bit token as 32 hex characters.
func newToken() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("udsmsg: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}
