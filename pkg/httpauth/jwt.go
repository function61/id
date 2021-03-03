package httpauth

import (
	"crypto/ecdsa"
	"fmt"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/function61/gokit/csrf"
	"github.com/patrickmn/go-cache"
)

type jwtSigner struct {
	privKey *ecdsa.PrivateKey
}

func NewEcJwtSigner(privateKey []byte) (Signer, error) {
	privKey, err := jwt.ParseECPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, err
	}

	return &jwtSigner{
		privKey: privKey,
	}, nil
}

func (j *jwtSigner) Sign(userDetails UserDetails, audience string, now time.Time) string {
	token := jwt.NewWithClaims(jwt.SigningMethodES512, jwt.StandardClaims{
		Subject:   userDetails.Id,
		Audience:  audience,
		ExpiresAt: now.Add(time.Hour * 24).Unix(),
	})

	tokenString, err := token.SignedString(j.privKey)
	if err != nil {
		panic(err)
	}

	return tokenString
}

type jwtAuthenticator struct {
	publicKey *ecdsa.PublicKey

	audience string

	// use caching for JWT validation, since ECDSA is pretty expensive, at least
	// when running on a Raspberry Pi Zero W each request takes seconds
	authCache *cache.Cache
}

func NewEcJwtAuthenticator(validatorPublicKey []byte, audience string) (HttpRequestAuthenticator, error) {
	publicKey, err := jwt.ParseECPublicKeyFromPEM(validatorPublicKey)
	if err != nil {
		return nil, err
	}

	return &jwtAuthenticator{
		publicKey: publicKey,

		audience: audience,

		// defaultExpiration doesn't matter, because we'll always push to cache with explicit TTLs
		authCache: cache.New(5*time.Minute, 10*time.Minute),
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
		// translate expired error
		if errValidation, is := err.(jwt.ValidationError); is && (errValidation.Errors&jwt.ValidationErrorExpired) != 0 {
			return nil, ErrSessionExpired
		}

		return nil, fmt.Errorf("JWT authentication: %w", err)
	}

	return NewUserDetails(claims.Subject, jwtString), nil
}

func (j *jwtAuthenticator) AuthenticateWithCsrfProtection(r *http.Request) (*UserDetails, error) {
	if err := csrf.Validate(r); err != nil {
		return nil, err
	}

	return j.Authenticate(r)
}

// wrap caching in its own "layer" so getValidatedClaims() is easier to audit
func (j *jwtAuthenticator) getValidatedClaimsCached(jwtString string) (*jwt.StandardClaims, error) {
	cachedClaims, isCached := j.authCache.Get(jwtString)
	if isCached {
		return cachedClaims.(*jwt.StandardClaims), nil
	}

	validatedClaims, err := j.getValidatedClaims(jwtString)
	// cache only if 1) claims valid 2) we have an expiration 3) expiration is in future
	if err == nil && validatedClaims.ExpiresAt != 0 {
		if untilExpiration := time.Until(time.Unix(validatedClaims.ExpiresAt, 0)); untilExpiration > 0 {
			j.authCache.Set(jwtString, validatedClaims, untilExpiration)
		}
	}

	return validatedClaims, err
}

func (j *jwtAuthenticator) getValidatedClaims(jwtString string) (*jwt.StandardClaims, error) {
	token, err := jwt.ParseWithClaims(jwtString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}

		return j.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims := token.Claims.(*jwt.StandardClaims)

	if j.audience != claims.Audience {
		return nil, fmt.Errorf("invalid audience: %s; expecting %s", claims.Audience, j.audience)
	}

	return claims, nil
}
