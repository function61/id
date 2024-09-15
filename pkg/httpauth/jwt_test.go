package httpauth

import (
	"crypto/ed25519"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/function61/gokit/testing/assert"
	"github.com/kataras/jwt"
	"github.com/patrickmn/go-cache"
)

func TestSignAndAuthenticate(t *testing.T) {
	signer, err := NewJwtSigner(testPrivateKey)
	assert.Ok(t, err)

	token := signer.Sign(UserDetails{Id: "123"}, "", time.Now())

	cookie := ToCookie(token)

	assert.Equal(t, cookie.Name, "auth")
	assert.Equal(t, cookie.Value, token)
	assert.Equal(t, cookie.HttpOnly, true)

	authenticator, _ := NewJwtAuthenticator(testPublicKey(), "")

	authenticateReq := func(req *http.Request) string {
		userDetails, err := authenticator.Authenticate(req)

		if err == nil {
			// cannot print whole JWT token because it contains random data for crypto
			return fmt.Sprintf("userid<%s> tok<%s>", userDetails.Id, userDetails.AuthTokenJwt[0:8]+"..")
		}

		return err.Error()
	}

	assert.Equal(t,
		authenticateReq(makeReq(nil)),
		"auth: either specify 'auth' cookie or 'Authorization' header")

	// authenticate via header instead of cookie

	reqWithBearerToken := makeReq(nil)
	reqWithBearerToken.Header.Set("Authorization", "Bearer "+cookie.Value)

	assert.Equal(t, authenticateReq(reqWithBearerToken), "userid<123> tok<eyJhbGci..>")
}

func TestSignAndAuthenticateMismatchingPublicKey(t *testing.T) {
	signer, err := NewJwtSigner(testPrivateKey)
	assert.Ok(t, err)

	// this public key is not linked to the private key
	authenticator, err := NewJwtAuthenticator(testMismatchingPublicKey, "")
	assert.Ok(t, err)

	token := signer.Sign(UserDetails{Id: "123"}, "", time.Now())

	_, err = authenticator.Authenticate(makeReq(ToCookie(token)))

	assert.Equal(t, err.Error(), "jwt: invalid token signature")
}

func TestTokenExpiry(t *testing.T) {
	signer, err := NewJwtSigner(testPrivateKey)
	assert.Ok(t, err)
	authenticator, err := NewJwtAuthenticator(testPublicKey(), "")
	assert.Ok(t, err)

	t0 := time.Date(2019, 2, 19, 15, 0, 0, 0, time.UTC)

	token := signer.Sign(UserDetails{Id: "123"}, "", t0)

	shouldBeValid := func(should bool) {
		t.Helper()
		userDetails, err := authenticator.Authenticate(makeReq(ToCookie(token)))

		if should {
			assert.Ok(t, err)
			assert.Equal(t, userDetails.Id, "123")
		} else {
			assert.Equal(t, err, ErrSessionExpired)
		}
	}

	timewarp := func(to time.Time, fnThatLivesInADifferentTime func()) {
		original := jwt.Clock
		defer func() {
			jwt.Clock = original
		}()

		jwt.Clock = func() time.Time {
			return to
		}

		authenticator.(*jwtAuthenticator).now = func() time.Time { return to }
		// caching (item TTLs) mess with timewarping
		authenticator.(*jwtAuthenticator).authCache = cache.New(5*time.Minute, 10*time.Minute)

		fnThatLivesInADifferentTime()
	}

	timewarp(t0, func() {
		shouldBeValid(true)
	})

	timewarp(t0.Add(8*time.Hour), func() {
		shouldBeValid(true)
	})

	timewarp(t0.Add(12*time.Hour), func() {
		shouldBeValid(true)
	})

	timewarp(t0.Add(23*time.Hour), func() {
		shouldBeValid(true)
	})

	timewarp(t0.Add(25*time.Hour), func() {
		shouldBeValid(false)
	})
}

func makeReq(cookie *http.Cookie) *http.Request {
	req, _ := http.NewRequest(http.MethodGet, "http://dummy/", nil)

	if cookie != nil {
		req.AddCookie(cookie)
	}

	return req
}

func testPublicKey() ed25519.PublicKey {
	return testPrivateKey.Public().(ed25519.PublicKey)
}

var (
	testPrivateKey           = ed25519.PrivateKey([]byte{126, 86, 13, 212, 219, 58, 93, 63, 4, 109, 247, 225, 203, 248, 124, 82, 139, 36, 234, 166, 151, 54, 141, 141, 195, 38, 13, 40, 129, 146, 205, 80, 253, 59, 144, 17, 84, 178, 224, 50, 235, 27, 110, 197, 219, 70, 101, 20, 226, 107, 140, 67, 34, 208, 255, 232, 118, 46, 249, 108, 120, 90, 11, 169})
	testMismatchingPublicKey = ed25519.PrivateKey([]byte{176, 169, 63, 92, 215, 99, 125, 50, 209, 19, 33, 16, 101, 5, 26, 2, 185, 240, 84, 110, 178, 215, 175, 249, 41, 125, 128, 176, 194, 161, 148, 140, 110, 111, 62, 67, 41, 105, 70, 245, 37, 162, 144, 233, 246, 25, 166, 215, 150, 86, 83, 106, 185, 43, 32, 89, 227, 146, 248, 1, 136, 219, 201, 169}).Public().(ed25519.PublicKey)
)
