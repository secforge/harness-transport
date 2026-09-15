package udsmsg

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Address schemes accepted as a reply target.
const (
	SchemeUDS    = "uds"
	SchemeBridge = "bridge"
	SchemeDID    = "did"
)

// addrRe mirrors the receiver's reply-address guard.
var addrRe = regexp.MustCompile(`^(?:uds|bridge|did):.{1,200}$`)

// sockNameRe mirrors the accepted socket file names: a plain pid, a pid with
// an 8-hex discriminator, or a 16-hex opaque id.
var sockNameRe = regexp.MustCompile(`^(\d+(-[0-9a-f]{8})?|[0-9a-f]{1,16})\.sock$`)

// ValidAddress reports whether addr is a well-shaped reply address. Shape is
// necessary but not sufficient: a uds: target must also resolve inside one of
// the standard socket directories, which ResolveReplyAddr checks.
func ValidAddress(addr string) bool { return addrRe.MatchString(addr) }

// UDSAddress formats a socket path as a uds: reply address.
func UDSAddress(path string) string { return SchemeUDS + ":" + path }

// ParseUDS extracts the socket path from a uds: address.
func ParseUDS(addr string) (path string, ok bool) {
	if !ValidAddress(addr) || !strings.HasPrefix(addr, SchemeUDS+":") {
		return "", false
	}
	return strings.TrimPrefix(addr, SchemeUDS+":"), true
}

// ValidSocketName reports whether name is an acceptable socket file name.
func ValidSocketName(name string) bool { return sockNameRe.MatchString(name) }

// PIDFromSocketName returns the pid encoded in a socket file name. Opaque
// 16-hex names carry no pid and return ok == false.
func PIDFromSocketName(name string) (pid int, ok bool) {
	if !ValidSocketName(name) {
		return 0, false
	}
	base := strings.TrimSuffix(name, ".sock")
	if i := strings.IndexByte(base, '-'); i >= 0 {
		base = base[:i]
	}
	n, err := strconv.Atoi(base)
	if err != nil {
		return 0, false
	}
	return n, true
}

// CheckDir verifies a socket directory is safe to use: mode 0700 and owned by
// the caller or root. A socket in a directory failing this check is refused by
// the receiver (ownerRefused), so binding there is pointless.
func CheckDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if perm := fi.Mode().Perm(); perm != 0o700 {
		return fmt.Errorf("%s has mode %#o, want 0700", dir, perm)
	}
	uid, err := ownerUID(fi)
	if err != nil {
		return err
	}
	if self := os.Getuid(); uid != uint32(self) && uid != 0 {
		return fmt.Errorf("%s is owned by uid %d, want %d or 0", dir, uid, self)
	}
	return nil
}

// ResolveReplyAddr validates a reply address for delivery. A uds: target must
// live in one of the standard socket directories; the receiver rejects
// anything else as "outside our socket namespace" unless the sender holds the
// reply_across_default_dirs capability.
func ResolveReplyAddr(addr string) (path string, err error) {
	p, ok := ParseUDS(addr)
	if !ok {
		return "", fmt.Errorf("not a well-shaped uds address: %q", addr)
	}
	dir := filepath.Dir(p)
	for _, std := range SocketDirs() {
		if dir == std {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s is outside the standard socket directories", p)
}
