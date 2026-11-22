package httpserver

import (
	"net"
	"net/http"
	"net/url"
	"strconv"

	"protectedauth/internal/auth"
)

func (h *handlers) root(w http.ResponseWriter, r *http.Request) {
	if len(r.Form) != 0 {
		message(w, http.StatusNotFound, "Страница не найдена.")

		return
	}

	h.showForm(w, r)
}

func (h *handlers) login(w http.ResponseWriter, r *http.Request) {
	if len(r.Form) == 0 {
		h.showForm(w, r)

		return
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		message(w, http.StatusBadRequest, "Некорректный адрес клиента.")

		return
	}

	retry, err := h.auth.AllowIP(r.Context(), ip, h.now())
	if err != nil {
		storageUnavailable(w)

		return
	}

	if retry > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		message(w, http.StatusTooManyRequests, "Превышен лимит попыток с этого IP.")

		return
	}

	params := r.Form
	if !params.Has("user_token") && params.Has("username") && params.Has("password") && params.Has("Login") {
		invalidToken(w)

		return
	}

	username := params.Get("username")
	password := params.Get("password")
	token := params.Get("user_token")

	if !validLogin(params, username, password, token) {
		message(w, http.StatusBadRequest, "Некорректные параметры.")

		return
	}

	id := sessionID(r)
	if !h.sessions.Consume(id, token) {
		invalidToken(w)

		return
	}

	result, err := h.auth.Authenticate(r.Context(), username, password)
	if err != nil {
		storageUnavailable(w)

		return
	}

	switch result {
	case auth.Success:
		current := h.sessions.Rotate(id, username)
		setSession(w, current.ID)
		render(w, http.StatusOK, "success", pageData{Username: username})

	case auth.AccountLocked:
		message(w, http.StatusTooManyRequests, "Вход заблокирован. Обратитесь к администратору.")

	case auth.InvalidCredentials:
		message(w, http.StatusUnauthorized, "Username and/or password incorrect.")

	default:
		storageUnavailable(w)
	}
}

func (h *handlers) showForm(w http.ResponseWriter, r *http.Request) {
	current := h.sessions.Form(sessionID(r))
	setSession(w, current.ID)

	render(w, http.StatusOK, "login", pageData{Token: current.Token})
}

func validParams(params url.Values, keys ...string) bool {
	if len(params) != len(keys) {
		return false
	}

	for _, key := range keys {
		if len(params[key]) != 1 {
			return false
		}
	}

	return true
}

func validLogin(params url.Values, username, password, token string) bool {
	return validParams(params, "username", "password", "user_token", "Login") &&
		params.Get("Login") == "Login" &&
		len(username) >= 1 && len(username) <= 64 &&
		len(password) >= 1 && len(password) <= 1024 &&
		len(token) <= 128
}

func invalidToken(w http.ResponseWriter) {
	message(w, http.StatusForbidden, "Недействительный или отсутствующий user_token.")
}

func storageUnavailable(w http.ResponseWriter) {
	message(w, http.StatusServiceUnavailable, "Хранилище недоступно. Вход закрыт.")
}
