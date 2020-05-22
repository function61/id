package idclient

import (
	"net/http"

	"github.com/function61/gokit/httpauth"
	"github.com/function61/gokit/sliceutil"
)

type Authorizer func(*http.Request, *httpauth.UserDetails) bool

func UserListAuthorizer(authorizedUserIds ...string) Authorizer {
	return func(r *http.Request, userDetails *httpauth.UserDetails) bool {
		return sliceutil.ContainsString(authorizedUserIds, userDetails.Id)
	}
}
