package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/function61/gokit/cryptoutil"
	"github.com/function61/gokit/envvar"
	"github.com/function61/gokit/httpauth"
	"github.com/function61/gokit/httputils"
	"github.com/function61/gokit/jsonfile"
	"github.com/gorilla/mux"
)

func newHttpHandler() (http.Handler, error) {
	router := mux.NewRouter()

	signer, signerPublicKey, err := loadSignerAndPublicKey()
	if err != nil {
		return nil, err
	}

	authenticator, err := httpauth.NewEcJwtAuthenticator(signerPublicKey)
	if err != nil {
		return nil, err
	}

	userRegistry := newUserRegistry()

	router.HandleFunc("/id", func(w http.ResponseWriter, r *http.Request) {
		nextValidated, err := getValidatedNext(r, redirectAllowList)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "text/html")

		if err := loginHtmlTpl.Execute(w, struct {
			Next              string
			NextHumanReadable string
		}{
			Next:              nextValidated.String(),
			NextHumanReadable: nextValidated.Host,
		}); err != nil {
			panic(err)
		}
	}).Methods(http.MethodGet)

	router.HandleFunc("/id", func(w http.ResponseWriter, r *http.Request) {
		nextValidated, err := getValidatedNext(r, redirectAllowList)
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

		jwt := signer.Sign(*userDetails, time.Now())

		log.Printf("login ok for %s", email)

		queryParams := nextValidated.Query()
		queryParams.Set("token", jwt)
		nextValidated.RawQuery = queryParams.Encode()

		httputils.NoCacheHeaders(w)
		http.Redirect(w, r, nextValidated.String(), http.StatusFound)
	}).Methods(http.MethodPost)

	router.HandleFunc("/id/profile", func(w http.ResponseWriter, r *http.Request) {
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

	router.HandleFunc("/id/logout", func(w http.ResponseWriter, r *http.Request) {
		httputils.NoCacheHeaders(w)

		http.SetCookie(w, httpauth.DeleteLoginCookie())

		fmt.Fprintln(w, "You have been logged out.")
	})

	router.HandleFunc("/id/signer.pub", func(w http.ResponseWriter, r *http.Request) {
		// https://stackoverflow.com/a/19517513
		w.Header().Set("Content-Type", "application/x-pem-file")

		fmt.Fprintln(w, string(signerPublicKey))
	})

	return router, nil
}

func getValidatedNext(r *http.Request, redirectAllowList []string) (*url.URL, error) {
	next := r.URL.Query().Get("next")
	if next == "" {
		return nil, errors.New("'next' not set")
	}

	nextUrl, err := url.Parse(next)
	if err != nil {
		return nil, fmt.Errorf("'next' not valid URL: %v", err)
	}

	if !hostMatchesAllowList(nextUrl.Host, redirectAllowList) {
		return nil, fmt.Errorf("'next' hostname (%s) not in allow list", nextUrl.Host)
	}

	return nextUrl, nil
}

func loadSignerAndPublicKey() (httpauth.Signer, []byte, error) {
	signingKey, err := loadSigningPrivateKey()
	if err != nil {
		return nil, nil, err
	}

	signer, err := httpauth.NewEcJwtSigner(signingKey)
	if err != nil {
		return nil, nil, err
	}

	// signer internally did this, but we need to do this again to get access to the pubkey
	privKey, err := jwt.ParseECPrivateKeyFromPEM(signingKey)
	if err != nil {
		return nil, nil, err
	}

	pubKeyMarshaled, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	return signer, cryptoutil.MarshalPemBytes(pubKeyMarshaled, cryptoutil.PemTypePublicKey), nil
}

func loadSigningPrivateKey() ([]byte, error) {
	pk, err := envvar.Required("SIGNING_PRIVATE_KEY")
	if err != nil {
		return nil, err
	}

	// PEM (= base64) isn't allowed to contain \ chars so this is OK
	return []byte(strings.ReplaceAll(pk, `\n`, "\n")), nil
}
