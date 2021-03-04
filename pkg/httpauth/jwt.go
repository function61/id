package httpauth

import (
	"crypto/ed25519"
	"net/http"
	"strings"
	"time"

	"github.com/kataras/jwt"
	"github.com/patrickmn/go-cache"
)

type jwtSigner struct {
	privKey ed25519.PrivateKey
}

func NewEcJwtSigner(privKey ed25519.PrivateKey) (Signer, error) {
	return &jwtSigner{
		privKey: privKey,
	}, nil
}

func (j *jwtSigner) Sign(userDetails UserDetails, audience string, now time.Time) string {
	tokenBytes, err := jwt.Sign(jwt.EdDSA, j.privKey, jwt.Claims{
		Audience: jwt.Audience{audience},
		Subject:  userDetails.Id,
		Expiry:   now.Add(24 * time.Hour).Unix(),
	})
	if err != nil {
		panic(err)
	}

	return string(tokenBytes)
}

type jwtAuthenticator struct {
	publicKey ed25519.PublicKey

	audience string

	// use caching for JWT validation, since these crypto opts are somewhat expensive, at least
	// when running on a Raspberry Pi Zero W each request takes seconds
	authCache *cache.Cache

	now func() time.Time // for testing
}

func NewEcJwtAuthenticator(publicKey ed25519.PublicKey, audience string) (HttpRequestAuthenticator, error) {
	return &jwtAuthenticator{
		publicKey: publicKey,

		audience: audience,

		// defaultExpiration doesn't matter, because we'll always push to cache with explicit TTLs
		authCache: cache.New(5*time.Minute, 10*time.Minute),

		now: time.Now,
	}, nil
}

func (j *jwtAuthenticator) Authenticate(r *http.Request) (*UserDetails, error) {
	// grab JWT either from:
	// 1) bearer token OR
	// 2) cookie
	jwtString := func() string {
		// first check if we have an authorization header
		authorizationHeader := r.Header.Get("Authorization")

		if strings.HasPrefix(authorizationHeader, "Bearer ") {
			return authorizationHeader[len("Bearer "):]
		}

		authCookie, err := r.Cookie(loginCookieName)
		if err != nil {
			return ""
		}

		return authCookie.Value
	}()

	if jwtString == "" {
		return nil, ErrNoAuthToken
	}

	return j.AuthenticateJwtString(jwtString)
}

func (j *jwtAuthenticator) AuthenticateJwtString(jwtString string) (*UserDetails, error) {
	claims, err := j.getValidatedClaimsCached(jwtString)
	if err != nil {
		if err == jwt.ErrExpired { // translate expired error
			return nil, ErrSessionExpired
		} else {
			// no need to wrap b/c errors seem to be prefixed with "jwt: "
			return nil, err
		}
	} else {
		return NewUserDetails(claims.Subject, jwtString), nil
	}
}

// wrap caching in its own "layer" so getValidatedClaims() is easier to audit
func (j *jwtAuthenticator) getValidatedClaimsCached(jwtString string) (*jwt.Claims, error) {
	cachedClaims, isCached := j.authCache.Get(jwtString)
	if isCached {
		return cachedClaims.(*jwt.Claims), nil
	}

	validClaims, err := j.getValidatedClaims(jwtString)
	// cache only if 1) claims valid 2) we have an expiration 3) expiration is in future
	if err == nil && validClaims.Expiry != 0 {
		if untilExpiration := j.until(validClaims.ExpiresAt()); untilExpiration > 0*time.Second {
			j.authCache.Set(jwtString, validClaims, untilExpiration)
		}
	}

	return validClaims, err
}

func (j *jwtAuthenticator) until(t time.Time) time.Duration {
	return t.Sub(j.now())
}

func (j *jwtAuthenticator) getValidatedClaims(jwtString string) (*jwt.Claims, error) {
	token, err := jwt.Verify(jwt.EdDSA, j.publicKey, []byte(jwtString), jwt.Expected{
		Audience: jwt.Audience{j.audience},
	})
	if err != nil {
		return nil, err
	}

	return &token.StandardClaims, nil
}
