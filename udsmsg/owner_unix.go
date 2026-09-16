//go:build unix

package udsmsg

import (
	"fmt"
	"io/fs"
	"syscall"
)

// ownerUID extracts the owning uid from a FileInfo.
func ownerUID(fi fs.FileInfo) (uint32, error) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("cannot read ownership of %s on this platform", fi.Name())
	}
	return st.Uid, nil
}
