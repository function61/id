package idclient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/function61/gokit/httpauth"
	"github.com/function61/gokit/httputils"
	"github.com/gorilla/mux"
)

type GatewayApi struct {
	client        *Client
	authenticator httpauth.HttpRequestAuthenticator
}

// This auth gateway is required because the identity server cannot set cookies in our behalf.
// The auth gateway simply takes the auth token from URL param, sets cookie and redirects forward.

func (c *Client) CreateAuthGateway(ctx context.Context, router *mux.Router) (*GatewayApi, error) {
	publicKey, err := c.obtainPublicKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("obtainPublicKey: %w", err)
	}

	authenticator, err := httpauth.NewEcJwtAuthenticator(publicKey)
	if err != nil {
		return nil, err
	}

	g := &GatewayApi{c, authenticator}

	g.registerGatewayRoutes(router)

	return g, nil
}

func (g *GatewayApi) LogoutUrl() string {
	return "/_auth/logout"
}

// wraps inner Handler with protection: 1) authentication 2) authorization
func (g *GatewayApi) Protect(authorizer Authorizer, authorizedHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// if this call returns false, response was also written
		if g.authenticateAndAuthorize(w, r, authorizer) {
			authorizedHandler.ServeHTTP(w, r)
		}
	})
}

// as own function mainly to make it easier to audit in which cases authorizedHandler is used
func (g *GatewayApi) authenticateAndAuthorize(
	w http.ResponseWriter,
	r *http.Request,
	authorizer Authorizer,
) bool {
	// 1) authentication
	authentication, err := g.authenticator.Authenticate(r)
	if err != nil {
		// TODO: detect .jpg, .css, .js etc.
		requestingAssets := false

		httputils.NoCacheHeaders(w)

		if !requestingAssets {
			// return via our gateway that sets the auth token
			http.Redirect(w, r, g.authUrlContinueToCurrent(r), http.StatusFound)
		} else {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		}
		return false
	}

	// 2) authorization
	if !authorizer(r, authentication) {
		// TODO: unset cookie?
		//       maybe not. if endpoint requires admin privileges, it would be wrong to
		//       kick out regular user
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return false
	}

	return true
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

func (g *GatewayApi) registerGatewayRoutes(router *mux.Router) *GatewayApi {
	// logs the user out from this website, but also the identity server
	router.HandleFunc("/_auth/logout", func(w http.ResponseWriter, r *http.Request) {
		httputils.NoCacheHeaders(w)

		// TODO: validate session, so an attacker can't force logout of user? this could be
		//       just enough due to cookie's SameSite=Strict ?

		http.SetCookie(w, httpauth.DeleteLoginCookie())

		http.Redirect(w, r, g.client.logoutUrl(), http.StatusFound)
	})

	router.HandleFunc("/_auth/redirect", func(w http.ResponseWriter, r *http.Request) {
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

		// validate JWT before setting cookie, so an attacker controlling the query
		// param can't set garbage JWT to force logout the user.
		//
		// the attacker still can set a valid JWT, so in effect can change victim's user.
		if _, err := g.authenticator.AuthenticateJwtString(jwt); err != nil {
			http.Error(w, "missing query param: jwt", http.StatusBadRequest)
			return
		}

		http.SetCookie(w, httpauth.ToCookie(jwt))

		httputils.NoCacheHeaders(w)

		http.Redirect(w, r, next, http.StatusFound)
	})

	return g
}

func validateRelativeRedirect(path string) (string, error) {
	// https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
	// TODO: research if this is adequate
	if strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//") {
		return path, nil
	}

	return "", fmt.Errorf("not a relative URL: %s", path)
}
