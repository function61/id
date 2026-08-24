package idclient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/function61/gokit/net/http/httputils"
	"github.com/function61/id/pkg/httpauth"
)

type GatewayAPI struct {
	client               *Client
	audience             string
	subroot              string
	authenticator        httpauth.HTTPRequestAuthenticator
	authenticatorBuildMu sync.Mutex
}

// This auth gateway is required because the identity server cannot set cookies on our behalf.
// The auth gateway simply takes the auth token from URL param, sets cookie and redirects forward.

func (c *Client) CreateAuthGateway(router *http.ServeMux, audience string, subroot string) *GatewayAPI {
	// we used to fetch the public key here, but that's not ideal. this CreateAuthGateway() is usually
	// called on application startup to protect specified/all HTTP routes. if we were to error here,
	// perhaps because network is down, it'd prevent starting the HTTP app.
	//
	// a better way is to require network connectivity only when it's needed, and defering this also
	// gets us re-tries on errors, i.e.:
	//
	// 1. Req 1 needs authentication - we return 500 because we can't reach ID server
	// 2. (ID server becomes back online)
	// 3. Req 2 needs authentication - now succeeds because we re-try fetching pubkey (b/c no cached entry)

	g := &GatewayAPI{
		client:   c,
		audience: audience,
		subroot:  subroot,
	}

	g.registerGatewayRoutes(router)

	return g
}

func (g *GatewayAPI) LogoutURL() string {
	return g.subroot + "/_auth/logout"
}

// wraps inner Handler with protection: 1) authentication 2) authorization
func (g *GatewayAPI) Protect(authorizer Authorizer, authorizedHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// if this call returns nil, response was also written
		if g.AuthenticateAndAuthorize(w, r, authorizer) != nil {
			authorizedHandler.ServeHTTP(w, r)
		}
	})
}

// returns UserDetails if user is authenticated & authorized.
// if returns nil, error response was already sent.
func (g *GatewayAPI) AuthenticateAndAuthorize(w http.ResponseWriter, r *http.Request, authorizer Authorizer) *httpauth.UserDetails {
	authenticator, err := g.getAuthenticator()
	if err != nil {
		http.Error(w, fmt.Sprintf("getAuthenticator: %v", err), http.StatusInternalServerError)
		return nil
	}

	// 1) authentication
	authentication, err := authenticator.Authenticate(r)
	if err != nil {
		switch err {
		case httpauth.ErrNoAuthToken, httpauth.ErrTokenExpired:
			// don't just blindly redirect all requests like .js, .jpg, .css etc.
			requestingHTML := strings.Contains(r.Header.Get("Accept"), "text/html")

			httputils.NoCacheHeaders(w)

			if requestingHTML {
				// return via our gateway that sets the auth token
				http.Redirect(w, r, g.authURLContinueToCurrent(r), http.StatusFound)
			} else {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			}
			return nil
		default: // some other error => display instead of redirect
			http.Error(w, err.Error(), http.StatusForbidden)
			return nil
		}
	}

	// 2) authorization
	if !authorizer(r, authentication) {
		// TODO: unset cookie?
		//       maybe not. if endpoint requires admin privileges, it would be wrong to
		//       kick out regular user
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return nil
	}

	return authentication
}

// continue to current path after logging in
func (g *GatewayAPI) authURLContinueToCurrent(r *http.Request) string {
	currentPath := r.URL.Path
	if r.URL.RawQuery != "" {
		// RawQuery doesn't have the "?"
		currentPath += "?" + r.URL.RawQuery
	}

	continueAfterGateway := currentPath

	return g.loginURLContinueToGateway(continueAfterGateway, r)
}

func (g *GatewayAPI) loginURLContinueToGateway(continueAfterGateway string, r *http.Request) string {
	// return back from auth with our gateway that'll set the auth cookie
	gateway := "https://" + r.Host + g.subroot + "/_auth/redirect?next=" + url.QueryEscape(continueAfterGateway)

	return g.client.loginURL(gateway)
}

func (g *GatewayAPI) registerGatewayRoutes(router *http.ServeMux) *GatewayAPI {
	router.HandleFunc(g.subroot+"/_auth/redirect", func(w http.ResponseWriter, r *http.Request) {
		// better set no-cache headers here, because URL already contains sensitive info
		httputils.NoCacheHeaders(w)

		next, err := validateRelativeRedirect(r.URL.Query().Get("next"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		jwt := r.URL.Query().Get("token")
		if jwt == "" {
			http.Error(w, "missing query param: token", http.StatusBadRequest)
			return
		}

		authenticator, err := g.getAuthenticator()
		if err != nil {
			http.Error(w, fmt.Sprintf("getAuthenticator: %v", err), http.StatusInternalServerError)
			return
		}

		// validate JWT before setting cookie, so an attacker controlling the query
		// param can't set garbage JWT to force logout the user.
		//
		// the attacker still can set a valid JWT, so in effect can change victim's user.
		userDetails, err := authenticator.AuthenticateJwtString(jwt)
		if err != nil {
			http.Error(w, "AuthenticateJwtString: "+err.Error(), http.StatusBadRequest)
			return
		}

		http.SetCookie(w, httpauth.ToCookie(jwt, &userDetails.Expiry, g.subroot))

		//nolint:gosec // not open redirect because has been validated as relative
		http.Redirect(w, r, next, http.StatusFound)
	})

	// logs the user out from this website, but also the identity server
	router.HandleFunc(g.subroot+"/_auth/logout", func(w http.ResponseWriter, r *http.Request) {
		httputils.NoCacheHeaders(w)

		// TODO: validate session, so an attacker can't force logout of user? this could be
		//       just enough due to cookie's SameSite=Strict ?

		http.SetCookie(w, httpauth.DeleteLoginCookie(g.subroot))

		http.Redirect(w, r, g.client.logoutURL(), http.StatusFound)
	})

	return g
}

func (g *GatewayAPI) getAuthenticator() (httpauth.HTTPRequestAuthenticator, error) {
	g.authenticatorBuildMu.Lock()
	defer g.authenticatorBuildMu.Unlock()

	if g.authenticator == nil {
		publicKey, err := g.client.ObtainPublicKey(context.Background())
		if err != nil {
			return nil, fmt.Errorf("ObtainPublicKey: %w", err)
		}

		authenticator, err := httpauth.NewJwtAuthenticator(publicKey, g.audience)
		if err != nil {
			return nil, fmt.Errorf("NewJwtAuthenticator: %w", err)
		}

		g.authenticator = authenticator
	}

	return g.authenticator, nil
}

// https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
func validateRelativeRedirect(path string) (string, error) {
	parsed, err := url.Parse(path)
	if err != nil {
		return "", err
	}

	if parsed.IsAbs() || parsed.Scheme != "" || parsed.Host != "" {
		return "", fmt.Errorf("not a relative URL: %s", path)
	}

	return path, nil
}
