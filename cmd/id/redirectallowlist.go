package main

import (
	"strings"
)

func hostMatchesAllowList(host string, allowList map[string]string) (bool, string) {
	for allow, audience := range allowList {
		switch {
		case host == allow:
			return true, audience
		case strings.HasPrefix(allow, "*") && strings.HasSuffix(host, allow[1:]): // *.example.com
			return true, audience
		}
	}

	return false, ""
}
