package httpserver

import (
	"net/http"

	"protectedauth/internal/session"
)

func sessionID(r *http.Request) string {
	cookie, err := r.Cookie("AUTH_SESSION")
	if err != nil {
		return ""
	}

	return cookie.Value
}

func setSession(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "AUTH_SESSION",
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(session.TTL.Seconds()),
	})
}
