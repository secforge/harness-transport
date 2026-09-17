package codexmsg

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"
)

// NewUUIDv7 returns a time-ordered version 7 UUID, the shape the Codex CLI
// uses for a queued message id. Ordering makes queued messages sort by when
// they were created, which a random v4 would not.
func NewUUIDv7() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("codexmsg: crypto/rand failed: " + err.Error())
	}
	ms := uint64(time.Now().UnixMilli())
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], ms<<16)
	copy(b[:6], ts[:6])
	b[6] = (b[6] & 0x0f) | 0x70
	b[8] = (b[8] & 0x3f) | 0x80
	return format(b)
}

func format(b [16]byte) string {
	h := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}
