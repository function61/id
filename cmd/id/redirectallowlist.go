package main

import (
	"strings"
)

func hostMatchesAllowList(host string, allowList []string) bool {
	for _, allow := range allowList {
		switch {
		case host == allow:
			return true
		case strings.HasPrefix(allow, "*") && strings.HasSuffix(host, allow[1:]): // *.example.com
			return true
		}
	}

	return false
}
