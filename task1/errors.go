package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

const errorLogPath = "/Users/maxim/study/beza/pr4/task1/dvwabrute-error.log"

type responseError struct {
	*httpResponse
	reason string
}

func (e *responseError) Error() string {
	preview := strings.Join(strings.Fields(e.body), " ")

	if len(preview) > 1500 {
		preview = preview[:1500] + " ... (полное тело — в журнале)"
	}

	if preview == "" {
		preview = "<пустое тело ответа>"
	}

	text := fmt.Sprintf("%s\nЗапрос: GET %s\nHTTP: %s\nВремя запроса: %s\nContent-Type: %s\nРазмер тела: %d байт; Content-Length: %d", e.reason, e.address, e.status, e.elapsed, e.contentType, len(e.body), e.declaredLength)

	if e.location != "" {
		text += "\nLocation: " + e.location
	}

	if e.retryAfter != "" {
		text += "\nRetry-After: " + e.retryAfter
	}

	return text + "\nОтвет (фрагмент): " + preview
}

func writeError(w io.Writer, err error, fullBody bool) {
	log.New(w, "", log.LstdFlags|log.Lmicroseconds).Printf("ERROR: %v", err)

	var responseErr *responseError

	if fullBody && errors.As(err, &responseErr) {
		fmt.Fprintf(w, "----- Тело HTTP-ответа -----\n%s\n----- Конец HTTP-ответа -----\n", responseErr.body)
	}
}

func reportError(err error) {
	writeError(os.Stderr, err, false)

	file, openErr := os.OpenFile(errorLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)

	if openErr != nil {
		fmt.Fprintf(os.Stderr, "Не удалось записать журнал %s: %v\n", errorLogPath, openErr)

		return
	}

	defer file.Close()

	writeError(file, err, true)
	fmt.Fprintln(os.Stderr, "Подробности записаны в", errorLogPath)
}
