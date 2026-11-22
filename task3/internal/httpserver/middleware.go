package httpserver

import "net/http"

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")

		next.ServeHTTP(w, r)
	})
}

func validateRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			message(w, http.StatusMethodNotAllowed, "Используйте GET.")

			return
		}

		if len(r.URL.RequestURI()) > 8192 {
			message(w, http.StatusRequestURITooLong, "Слишком длинный запрос.")

			return
		}

		if err := r.ParseForm(); err != nil || len(r.Form) > 12 {
			message(w, http.StatusBadRequest, "Некорректные параметры.")

			return
		}

		next.ServeHTTP(w, r)
	})
}
