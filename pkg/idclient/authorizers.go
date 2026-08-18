package idclient

import (
	"net/http"
	"slices"

	"github.com/function61/id/pkg/httpauth"
)

type Authorizer func(*http.Request, *httpauth.UserDetails) bool

func UserListAuthorizer(authorizedUserIds ...string) Authorizer {
	return func(r *http.Request, userDetails *httpauth.UserDetails) bool {
		// anonymous can never be authorized. protects from case where 2 things have gone wrong:
		// - authorizedUserIds accidentally contains empty item
		// - JWT was signed with an empty user ID
		if userDetails.ID == "" {
			return false
		}

		return slices.Contains(authorizedUserIds, userDetails.ID)
	}
}
