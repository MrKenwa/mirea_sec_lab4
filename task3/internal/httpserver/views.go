package httpserver

import (
	"bytes"
	"embed"
	"html/template"
	"net/http"
)

//go:embed templates/*.html
var templateFiles embed.FS

var pages = template.Must(template.ParseFS(templateFiles, "templates/*.html"))

type pageData struct {
	Username string
	Token    string
	Message  string
}

func render(w http.ResponseWriter, status int, page string, data pageData) {
	var body bytes.Buffer

	if err := pages.ExecuteTemplate(&body, page, data); err != nil {
		http.Error(w, "Не удалось сформировать страницу.", http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = body.WriteTo(w)
}

func message(w http.ResponseWriter, status int, text string) {
	render(w, status, "message", pageData{Message: text})
}
