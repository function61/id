package httpauth

import (
	"errors"
	"net/http"
	"time"
)

var (
	ErrTokenExpired = errors.New("auth: session expired")
	ErrNoAuthToken  = errors.New("auth: either specify '" + loginCookieName + "' cookie or 'Authorization' header")
)

type RequestContext struct {
	User *UserDetails
}

type UserDetails struct {
	Id           string
	AuthTokenJwt string // the JWT token that was used for auth
}

func NewUserDetails(id string, authTokenJwt string) *UserDetails {
	return &UserDetails{id, authTokenJwt}
}

type HttpRequestAuthenticator interface {
	// authenticates a Request. error is ErrNoAuthToken if no auth details and ErrSessionExpired if auth token expired
	Authenticate(req *http.Request) (*UserDetails, error)
	AuthenticateJwtString(jwtString string) (*UserDetails, error)
}

type Signer interface {
	Sign(userDetails UserDetails, audience string, now time.Time) string
}

// if returns nul, request handling is aborted.
// in return=nil case middleware is responsible for error response.
type MiddlewareChain func(w http.ResponseWriter, r *http.Request) *RequestContext

type MiddlewareChainMap map[string]MiddlewareChain
