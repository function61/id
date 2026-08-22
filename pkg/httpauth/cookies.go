package httpauth

import (
	"net/http"
	"time"
)

const (
	loginCookieName = "auth"
)

func ToCookie(tokenString string, expires *time.Time) *http.Cookie {
	if expires == nil { // when expiration not given it is intended to expire when the browser session ends.. dunno if that's what we want.
		expires = &time.Time{}
	}

	// https://stackoverflow.com/questions/42216700/how-can-i-redirect-after-oauth2-with-samesite-strict-and-still-get-my-cookies
	return &http.Cookie{
		Name:     loginCookieName,
		Value:    tokenString,
		Expires:  *expires,
		Path:     "/",
		HttpOnly: true,                 // = not visible to JavaScript, to protect from XSS
		SameSite: http.SameSiteLaxMode, // CSRF protection (no strict b/c cookies+redirects don't work)
		Secure:   true,                 // only submit over https
	}
}

func DeleteLoginCookie() *http.Cookie {
	// NOTE: keep cookie attributes in sync with ToCookie(), since the cookies may be
	//       considered separate cookies, unless components like "Path" (might be more) match
	return &http.Cookie{
		Name:     loginCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1, // => delete
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // CSRF protection (no strict b/c cookies+redirects don't work)
		Secure:   true,                 // only submit over https
	}
}
