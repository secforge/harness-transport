//go:build !unix

package udsmsg

import (
	"fmt"
	"io/fs"
)

// ownerUID has no meaning here: Windows does not express file ownership as a
// numeric uid, and the directory check this feeds exists to establish that a
// socket directory belongs to us and nobody else.
//
// It fails rather than returning 0, which would compare equal to root and
// quietly turn an ownership check into a check that passes.
func ownerUID(fi fs.FileInfo) (uint32, error) {
	return 0, fmt.Errorf("file ownership cannot be read as a uid on this platform, so %s cannot be verified", fi.Name())
}
