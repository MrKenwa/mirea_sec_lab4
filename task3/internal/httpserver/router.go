// Package httpserver содержит маршрутизацию и HTTP-обработчики авторизации.
package httpserver

import (
	"context"
	"net/http"
	"time"

	"protectedauth/internal/auth"
	"protectedauth/internal/session"
)

const LoginPath = "/vulnerabilities/brute/"

type Authenticator interface {
	Authenticate(context.Context, string, string) (auth.Result, error)
	AllowIP(context.Context, string, time.Time) (int, error)
}

type handlers struct {
	auth     Authenticator
	sessions *session.Manager
	now      func() time.Time
}

func New(authenticator Authenticator, sessions *session.Manager, now func() time.Time) http.Handler {
	h := &handlers{auth: authenticator, sessions: sessions, now: now}
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", h.root)
	mux.HandleFunc("GET "+LoginPath+"{$}", h.login)
	mux.HandleFunc("GET /protected/{$}", h.protected)
	mux.HandleFunc("GET /logout/{$}", h.logout)

	return securityHeaders(validateRequest(mux))
}
