package udsmsg

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// SchemeUDS is the only reply-address scheme observed on this transport.
const SchemeUDS = "uds"

// addrRe is the reply-address shape this package accepts. Observed addresses
// are uds:, and nothing else is recognised: an address shape accepted here is
// one this package is willing to resolve and send to.
var addrRe = regexp.MustCompile(`^uds:.{1,200}$`)

// dialNameRe is what this package will CONNECT TO. It is deliberately wider:
// refusing to answer an address because its name is unfamiliar costs a reply,
// while the name itself grants nothing — safety here comes from the directory
// being 0700 and ours (CheckDir) and from the kernel's credentials, not from
// the spelling. It still excludes anything that is not a plain ".sock" leaf:
// no separators, no traversal, no empty stem.
var dialNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}\.sock$`)

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

// ValidSocketName reports whether name is one this package will connect to.
func ValidSocketName(name string) bool {
	return name != ".sock" && !strings.Contains(name, "..") && dialNameRe.MatchString(name)
}

// PIDFromSocketName returns the pid encoded in a socket file name. A name that
// does not carry one returns ok == false, which is not an error: a peer may
// name its inbox anything, and the pid is simply unavailable then.
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
