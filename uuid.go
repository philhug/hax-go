package hax

import (
	"crypto/rand"
	"fmt"
)

// uuidV4 generates a random UUID v4 string.
func uuidV4() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("hax: crypto/rand failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
