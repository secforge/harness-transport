package deliver

import (
	"os/exec"
	"strings"
	"testing"
)

// A consumer publishes five platform binaries from one tree, so a compile
// break on any of them stops a release. It happened once: SO_PEERCRED went in
// with no build tag and surfaced during publication. Building here moves that
// to the commit that causes it.
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
