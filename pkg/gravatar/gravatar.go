// gravatar.com API
package gravatar

import (
	"crypto/md5" //nolint:gosec // ok, needed
	"fmt"
	"strings"
)

const (
	DefaultIdenticon = "identicon"
)

func Avatar(email string, defaultTo string) string {
	return fmt.Sprintf(
		"https://www.gravatar.com/avatar/%x?d=%s",
		//nolint:gosec // ok, needed
		md5.Sum([]byte(strings.ToLower(email))),
		defaultTo)
}
