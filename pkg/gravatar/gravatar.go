// gravatar.com API
package gravatar

import (
	"crypto/md5"
	"fmt"
	"strings"
)

const (
	DefaultIdenticon = "identicon"
)

func Avatar(email string, defaultTo string) string {
	return fmt.Sprintf(
		"https://www.gravatar.com/avatar/%x?d=%s",
		md5.Sum([]byte(strings.ToLower(email))),
		defaultTo)
}
