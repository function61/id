package main

import (
	"bytes"
	"crypto/ed25519"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"time"

	"github.com/function61/gokit/encoding/jsonfile"
	"github.com/function61/gokit/net/http/httputils"
	"github.com/function61/gokit/os/osutil"
	"github.com/function61/id/pkg/httpauth"
	"gopkg.in/square/go-jose.v2"
)

//go:embed templates
var templateFiles embed.FS

var templates, _ = template.ParseFS(templateFiles, "templates/*.html")

func newHttpHandler() (http.Handler, error) {
	router := http.NewServeMux()

	signer, signerPublicKey, err := loadSignerAndPublicKey()
	if err != nil {
		return nil, err
	}

	signerPubKeySetJson, err := makeSignerKeySet(signerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("makeSignerKeySet: %w", err)
	}

	authenticator, err := httpauth.NewJwtAuthenticator(signerPublicKey, "")
	if err != nil {
		return nil, err
	}

	userRegistry := newUserRegistry()

	router.HandleFunc("GET /id", func(w http.ResponseWriter, r *http.Request) {
		nextValidated, _, err := getValidatedNext(r, redirectAllowList)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "text/html")

		if err := templates.Lookup("login.html").Execute(w, struct {
			Next              string
			NextHumanReadable string
			BackgroundImage   string
		}{
			Next:              nextValidated.String(),
			NextHumanReadable: nextValidated.Host,
			BackgroundImage:   randomBackgroundImage(),
		}); err != nil {
			panic(err)
		}
	})

	router.HandleFunc("POST /id", func(w http.ResponseWriter, r *http.Request) {
		nextValidated, audience, err := getValidatedNext(r, redirectAllowList)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		email := r.PostFormValue("email")
		password := r.PostFormValue("password")

		if email == "" || password == "" {
			http.Error(w, "email or password empty", http.StatusBadRequest)
			return
		}

		user := userRegistry.CheckLogin(email, password)
		if user == nil {
			// TODO: ponder about this. OTOH PBKDF2 has built-in slowness, but things could
			//       change when running on Lambda?
			time.Sleep(2 * time.Second)

			http.Error(w, "invalid email or password", http.StatusForbidden)
			return
		}

		userDetails := httpauth.NewUserDetails(user.Id, "")

		jwt := signer.Sign(*userDetails, audience, time.Now())

		log.Printf("login ok for %s", email)

		queryParams := nextValidated.Query()
		queryParams.Set("token", jwt)
		nextValidated.RawQuery = queryParams.Encode()

		httputils.NoCacheHeaders(w)
		http.Redirect(w, r, nextValidated.String(), http.StatusFound)
	})

	router.HandleFunc("GET /id/profile", func(w http.ResponseWriter, r *http.Request) {
		auth, err := authenticator.Authenticate(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		user := userRegistry.UserById(auth.Id)
		if user == nil {
			http.Error(w, "authenticated user not found", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = jsonfile.Marshal(w, &user)
	})

	router.HandleFunc("GET /id/logout", func(w http.ResponseWriter, r *http.Request) {
		httputils.NoCacheHeaders(w)

		http.SetCookie(w, httpauth.DeleteLoginCookie())

		fmt.Fprintln(w, "You have been logged out.")
	})

	router.HandleFunc("GET /id/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		// https://tools.ietf.org/html/rfc7517
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(signerPubKeySetJson)
	})

	return router, nil
}

func getValidatedNext(r *http.Request, redirectAllowList map[string]string) (*url.URL, string, error) {
	next := r.URL.Query().Get("next")
	if next == "" {
		return nil, "", errors.New("'next' not set")
	}

	nextUrl, err := url.Parse(next)
	if err != nil {
		return nil, "", fmt.Errorf("'next' not valid URL: %v", err)
	}

	matches, audience := hostMatchesAllowList(nextUrl.Host, redirectAllowList)
	if !matches {
		return nil, "", fmt.Errorf("'next' hostname (%s) not in allow list", nextUrl.Host)
	}

	return nextUrl, audience, nil
}

func loadSignerAndPublicKey() (httpauth.Signer, ed25519.PublicKey, error) {
	signingKey, err := loadSigningPrivateKey()
	if err != nil {
		return nil, nil, err
	}

	signer, err := httpauth.NewJwtSigner(signingKey)
	if err != nil {
		return nil, nil, err
	}

	return signer, signingKey.Public().(ed25519.PublicKey), nil
}

func loadSigningPrivateKey() (ed25519.PrivateKey, error) {
	pk, err := osutil.GetenvRequired("SIGNING_PRIVATE_KEY")
	if err != nil {
		return nil, err
	}

	return unmarshalPrivateKey(pk)
}

func randomBackgroundImage() string {
	maxBackgroundNumber := 20

	// Intn() returns between 1 and n-1 so we'll adjust to between (1, n)
	//nolint:gosec // weak RNG ok
	backgroundNumber := 1 + rand.Intn(maxBackgroundNumber)
	return fmt.Sprintf(
		"https://function61.com/files/id-backgrounds/%d.jpg",
		backgroundNumber)
}

func makeSignerKeySet(signerPublicKey ed25519.PublicKey) ([]byte, error) {
	jwk := jose.JSONWebKey{
		Key: signerPublicKey,
	}

	keySetJson := bytes.Buffer{}
	if err := jsonfile.Marshal(&keySetJson, jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}); err != nil {
		return nil, err
	}

	return keySetJson.Bytes(), nil
}
