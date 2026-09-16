package deliver

import (
	"os/exec"
	"strings"
	"testing"
)

// This library is consumed by a project that publishes five platform binaries
// from one tree, so a compile break on any of them is not an inconvenience —
// it stops a release, and it is discovered at the worst possible moment.
//
// It happened: SO_PEERCRED went in with no build tag, and the first thing to
// notice was a cross-compile during publication. Building here means the
// break surfaces on the commit that causes it.
func TestEveryReleasePlatformBuilds(t *testing.T) {
	if testing.Short() {
		t.Skip("cross-compiling every target is slow")
	}
	for _, target := range []struct{ goos, goarch string }{
		{"linux", "amd64"},
		{"linux", "arm64"},
		{"darwin", "amd64"},
		{"darwin", "arm64"},
		{"windows", "amd64"},
	} {
		cmd := exec.Command("go", "build", "./...")
		cmd.Dir = ".."
		cmd.Env = append(cmd.Environ(), "GOOS="+target.goos, "GOARCH="+target.goarch)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s/%s does not build:\n%s", target.goos, target.goarch,
				strings.TrimSpace(string(out)))
		}
	}
}
