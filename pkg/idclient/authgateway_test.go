package idclient

import (
	"net/http"
	"net/url"
	"testing"

	. "github.com/function61/gokit/builtin"
	"github.com/function61/gokit/testing/assert"
)

func TestAuthUrlContinueToCurrent(t *testing.T) {
	url_ := Must(url.Parse("https://loppi.org/assets/view?id=foobar"))
	g := GatewayAPI{
		client:  New(Function61),
		subroot: "/assets",
	}
	u := g.authURLContinueToCurrent(&http.Request{
		Host: url_.Host,
		URL:  url_,
	})
	assert.Equal(t, u, "https://function61.com/id?next=https%3A%2F%2Floppi.org%2Fassets%2F_auth%2Fredirect%3Fnext%3D%252Fassets%252Fview%253Fid%253Dfoobar")

	parsed := Must(url.Parse(u))

	nextRaw := parsed.Query().Get("next")
	assert.Equal(t, nextRaw, "https://loppi.org/assets/_auth/redirect?next=%2Fassets%2Fview%3Fid%3Dfoobar")

	next := Must(url.Parse(nextRaw))
	assert.Equal(t, next.Query().Get("next"), "/assets/view?id=foobar")
}
