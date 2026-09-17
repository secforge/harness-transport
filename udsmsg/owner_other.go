//go:build !unix

package udsmsg

import (
	"fmt"
	"io/fs"
)

// ownerUID has no meaning here: Windows does not express ownership as a uid.
// It fails rather than returning 0, which compares equal to root and would
// turn the directory check into one that always passes.
func ownerUID(fi fs.FileInfo) (uint32, error) {
	return 0, fmt.Errorf("file ownership cannot be read as a uid on this platform, so %s cannot be verified", fi.Name())
}
