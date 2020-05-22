package main

import (
	"testing"

	"github.com/function61/gokit/assert"
)

func TestHostMatchesAllowList(t *testing.T) {
	allowList := []string{
		"*.prod.example.net",
		"foobar.com",
	}

	for _, tc := range []struct {
		host    string
		matches bool
	}{
		{
			host:    "grafana.prod.example.net",
			matches: true,
		},
		{
			host:    "grafana.sub.prod.example.net",
			matches: true,
		},
		{
			host:    "prod.example.net", // intentionally does not match
			matches: false,
		},
		{
			host:    "grafana.prod.example.net.attacker.com",
			matches: false,
		},
		{
			host:    "foobar.com",
			matches: true,
		},
		{
			host:    "sub.foobar.com",
			matches: false,
		},
		{
			host:    "xfoobar.com",
			matches: false,
		},
		{
			host:    ".foobar.com",
			matches: false,
		},
	} {
		tc := tc // pin

		t.Run(tc.host, func(t *testing.T) {
			assert.Assert(t, hostMatchesAllowList(tc.host, allowList) == tc.matches)
		})
	}
}
