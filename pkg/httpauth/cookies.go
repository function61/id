package httpauth

import (
	"net/http"
	"time"
)

const (
	loginCookieName = "auth"
)

func ToCookie(tokenString string, expires *time.Time, subroot string) *http.Cookie {
	if expires == nil { // when expiration not given it is intended to expire when the browser session ends.. dunno if that's what we want.
		expires = &time.Time{}
	}

	// https://stackoverflow.com/questions/42216700/how-can-i-redirect-after-oauth2-with-samesite-strict-and-still-get-my-cookies
	return &http.Cookie{
		Name:     loginCookieName,
		Value:    tokenString,
		Expires:  *expires,
		Path:     cookiePathFromSubroot(subroot),
		HttpOnly: true,                 // = not visible to JavaScript, to protect from XSS
		SameSite: http.SameSiteLaxMode, // CSRF protection (no strict b/c cookies+redirects don't work)
		Secure:   true,                 // only submit over https
	}
}

func DeleteLoginCookie(subroot string) *http.Cookie {
	// NOTE: keep cookie attributes in sync with ToCookie(), since the cookies may be
	//       considered separate cookies, unless components like "Path" (might be more) match
	return &http.Cookie{
		Name:     loginCookieName,
		Value:    "",
		Path:     cookiePathFromSubroot(subroot),
		MaxAge:   -1, // => delete
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // CSRF protection (no strict b/c cookies+redirects don't work)
		Secure:   true,                 // only submit over https
	}
}

// don't want to unconditionally add `/` to end of `subroot` because if subroot is `/files` we want to enable cookie for
// that path as well and not just `/files/`
func cookiePathFromSubroot(subroot string) string {
	if subroot == "" {
		return "/"
	}
	return subroot
}
