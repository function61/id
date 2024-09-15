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

type GatewayApi struct {
	client               *Client
	audience             string
	authenticator        httpauth.HttpRequestAuthenticator
	authenticatorBuildMu sync.Mutex
}

// This auth gateway is required because the identity server cannot set cookies on our behalf.
// The auth gateway simply takes the auth token from URL param, sets cookie and redirects forward.

func (c *Client) CreateAuthGateway(router *http.ServeMux, audience string) *GatewayApi {
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

	g := &GatewayApi{
		client:   c,
		audience: audience,
	}

	g.registerGatewayRoutes(router)

	return g
}

func (g *GatewayApi) LogoutUrl() string {
	return "/_auth/logout"
}

// wraps inner Handler with protection: 1) authentication 2) authorization
func (g *GatewayApi) Protect(authorizer Authorizer, authorizedHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// if this call returns nil, response was also written
		if g.AuthenticateAndAuthorize(w, r, authorizer) != nil {
			authorizedHandler.ServeHTTP(w, r)
		}
	})
}

// returns UserDetails if user is authenticated & authorized.
// if returns nil, error response was already sent.
func (g *GatewayApi) AuthenticateAndAuthorize(
	w http.ResponseWriter,
	r *http.Request,
	authorizer Authorizer,
) *httpauth.UserDetails {
	authenticator, err := g.getAuthenticator()
	if err != nil {
		http.Error(w, fmt.Sprintf("getAuthenticator: %v", err), http.StatusInternalServerError)
		return nil
	}

	// 1) authentication
	authentication, err := authenticator.Authenticate(r)
	if err != nil {
		switch {
		case err == httpauth.ErrNoAuthToken, err == httpauth.ErrTokenExpired:
			// don't just blindly redirect all requests like .js, .jpg, .css etc.
			requestingHtml := strings.Contains(r.Header.Get("Accept"), "text/html")

			httputils.NoCacheHeaders(w)

			if requestingHtml {
				// return via our gateway that sets the auth token
				http.Redirect(w, r, g.authUrlContinueToCurrent(r), http.StatusFound)
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
func (g *GatewayApi) authUrlContinueToCurrent(r *http.Request) string {
	currentPath := r.URL.Path + r.URL.RawQuery

	continueAfterGateway := currentPath

	return g.loginUrlContinueToGateway(continueAfterGateway, r)
}

func (g *GatewayApi) loginUrlContinueToGateway(continueAfterGateway string, r *http.Request) string {
	// return back from auth with our gateway that'll set the auth cookie
	gateway := "https://" + r.Host + "/_auth/redirect?next=" + url.QueryEscape(continueAfterGateway)

	return g.client.loginUrl(gateway)
}

func (g *GatewayApi) registerGatewayRoutes(router *http.ServeMux) *GatewayApi {
	// logs the user out from this website, but also the identity server
	router.HandleFunc("/_auth/logout", func(w http.ResponseWriter, r *http.Request) {
		httputils.NoCacheHeaders(w)

		// TODO: validate session, so an attacker can't force logout of user? this could be
		//       just enough due to cookie's SameSite=Strict ?

		http.SetCookie(w, httpauth.DeleteLoginCookie())

		http.Redirect(w, r, g.client.logoutUrl(), http.StatusFound)
	})

	router.HandleFunc("/_auth/redirect", func(w http.ResponseWriter, r *http.Request) {
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
		if _, err := authenticator.AuthenticateJwtString(jwt); err != nil {
			http.Error(w, "AuthenticateJwtString: "+err.Error(), http.StatusBadRequest)
			return
		}

		http.SetCookie(w, httpauth.ToCookie(jwt))

		http.Redirect(w, r, next, http.StatusFound)
	})

	return g
}

func (g *GatewayApi) getAuthenticator() (httpauth.HttpRequestAuthenticator, error) {
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

func validateRelativeRedirect(path string) (string, error) {
	// https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
	// TODO: research if this is adequate
	if strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//") {
		return path, nil
	}

	return "", fmt.Errorf("not a relative URL: %s", path)
}
