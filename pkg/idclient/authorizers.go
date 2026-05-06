package idclient

import (
	"net/http"
	"slices"

	"github.com/function61/id/pkg/httpauth"
)

type Authorizer func(*http.Request, *httpauth.UserDetails) bool

func UserListAuthorizer(authorizedUserIds ...string) Authorizer {
	return func(r *http.Request, userDetails *httpauth.UserDetails) bool {
		return slices.Contains(authorizedUserIds, userDetails.Id)
	}
}
