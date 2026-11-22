package httpserver

import "net/http"

func (h *handlers) protected(w http.ResponseWriter, r *http.Request) {
	current, ok := h.sessions.Protected(sessionID(r))
	if !ok {
		message(w, http.StatusUnauthorized, "Требуется вход.")

		return
	}

	render(w, http.StatusOK, "protected", pageData{
		Username: current.Username,
		Token:    current.Token,
	})
}

func (h *handlers) logout(w http.ResponseWriter, r *http.Request) {
	if !validParams(r.Form, "user_token") || !h.sessions.Logout(sessionID(r), r.Form.Get("user_token")) {
		message(w, http.StatusForbidden, "Недействительный токен выхода.")

		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "AUTH_SESSION",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	message(w, http.StatusOK, "Вы вышли.")
}
