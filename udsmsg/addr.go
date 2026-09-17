package udsmsg

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// schemeUDS is the only reply-address scheme observed on this transport.
const schemeUDS = "uds"

// maxSocketPath is the longest path a unix socket can have: sun_path is 108
// bytes and holds a NUL-terminated string. A longer address names a socket
// nothing could have bound, so both address guards below are built from this
// rather than from a chosen number.
const maxSocketPath = 107

// addrRe is the reply-address shape this package accepts. Observed addresses
// are uds:, and nothing else is recognised: an address shape accepted here is
// one this package is willing to resolve and send to.
var addrRe = regexp.MustCompile(fmt.Sprintf(`^%s:.{1,%d}$`, schemeUDS, maxSocketPath))

// dialNameRe is what this package will CONNECT TO, deliberately wider than
// what it binds: a name grants nothing, safety comes from checkDir and the
// kernel's credentials, and refusing an unfamiliar one only costs a reply. It
// still excludes anything that is not a plain ".sock" leaf.
var dialNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}\.sock$`)

// validAddress reports whether addr is a well-shaped reply address. Shape is
// necessary and not sufficient: whether the socket it names is one worth
// connecting to is decided when connecting, by checkDir on its directory.
func validAddress(addr string) bool { return addrRe.MatchString(addr) }

// udsAddress formats a socket path as a uds: reply address.
func udsAddress(path string) string { return schemeUDS + ":" + path }

// validSocketName reports whether name is one this package will connect to.
func validSocketName(name string) bool {
	return name != ".sock" && !strings.Contains(name, "..") && dialNameRe.MatchString(name)
}

// PIDFromSocketName returns the pid encoded in a socket file name. A name that
// does not carry one returns ok == false, which is not an error: a peer may
// name its inbox anything, and the pid is simply unavailable then.
func PIDFromSocketName(name string) (pid int, ok bool) {
	if !validSocketName(name) {
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

// checkDir verifies a socket directory is safe to use: mode 0700 and owned by
// the caller or root. That is the whole boundary this transport rests on — the
// token in a key file protects nothing a same-uid process cannot already read,
// so a directory anyone else can enter makes the socket inside it public.
func checkDir(dir string) error {
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
