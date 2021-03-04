package main

import (
	"testing"

	"github.com/function61/gokit/assert"
)

func TestHostMatchesAllowList(t *testing.T) {
	allowList := map[string]string{
		"*.prod.example.net": "t-1/site",
		"foobar.com":         "t-2/site",
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
			match, _ := hostMatchesAllowList(tc.host, allowList)
			assert.Assert(t, match == tc.matches)
		})
	}
}
