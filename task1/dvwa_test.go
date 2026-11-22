package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Проверяем HTTP-протокол целиком: параметры, cookie и ответы формы.
func TestFormProtocol(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Query().Get("username") != "admin" || r.URL.Query().Get("Login") != "Login" {
			t.Error("неверный запрос формы")
		}

		session, _ := r.Cookie("PHPSESSID")
		security, _ := r.Cookie("security")

		if session == nil || session.Value != "test-session" || security == nil || security.Value != "low" {
			t.Error("неверные cookie")
		}

		if r.URL.Query().Get("password") == "a+& ?" {
			fmt.Fprint(w, "<p>Welcome to the password protected area admin</p>")
		} else {
			fmt.Fprint(w, "Username and/or password incorrect.")
		}
	}))

	defer server.Close()

	target := newDVWA("test-session", 2)
	target.endpoint = server.URL

	for _, password := range []string{"wrong", "a+& ?"} {
		found, err := target.check(context.Background(), []byte(password))

		if err != nil || found != (password == "a+& ?") {
			t.Fatalf("found=%v err=%v", found, err)
		}
	}
}

func TestFormErrorsAreNotWrongPasswords(t *testing.T) {
	for _, status := range []int{http.StatusFound, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusOK} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/login.php")
				w.WriteHeader(status)
				fmt.Fprint(w, "<form>Login to DVWA</form>")
			}))

			defer server.Close()

			target := newDVWA("test-session", 2)
			target.endpoint = server.URL

			if found, err := target.check(context.Background(), []byte("x")); found || err == nil {
				t.Fatalf("found=%v err=%v", found, err)
			}
		})
	}
}

func TestSearchOverHTTP(t *testing.T) {
	for _, wanted := range []string{"12", "not-in-range"} {
		t.Run(wanted, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("password") == wanted {
					fmt.Fprint(w, "Welcome to the password protected area admin")
				} else {
					fmt.Fprint(w, "Username and/or password incorrect.")
				}
			}))

			defer server.Close()

			target := newDVWA("test-session", 2)
			target.endpoint = server.URL
			charset, _ := ResolveCharset("digits")
			cfg, _ := NewConfig(charset, 2, 2, 2)
			result, err := search(context.Background(), cfg, target)

			if err != nil {
				t.Fatal(err)
			}

			if wanted == "12" && (result.Status != "found" || result.Password != "12") {
				t.Fatalf("%+v", result)
			}

			if wanted != "12" && (result.Status != "exhausted" || result.Attempts != 100) {
				t.Fatalf("%+v", result)
			}
		})
	}
}

func TestSearchCancelsRequests(t *testing.T) {
	entered := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	}))

	defer server.Close()

	target := newDVWA("test-session", 1)
	target.endpoint = server.URL
	charset, _ := ResolveCharset("digits")
	cfg, _ := NewConfig(charset, 1, 1, 1)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	done := make(chan error, 1)

	go func() {
		_, err := search(ctx, cfg, target)

		done <- err
	}()

	select {
	case <-entered:

	case <-time.After(3 * time.Second):
		t.Fatal("запрос не начался")
	}

	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("нет ошибки отмены")
		}

	case <-time.After(3 * time.Second):
		t.Fatal("запрос не отменён")
	}
}

func TestReadCookies(t *testing.T) {
	file := filepath.Join(t.TempDir(), "cookies.txt")
	contents := "# Netscape HTTP Cookie File\n127.0.0.1\tFALSE\t/\tFALSE\t0\tsecurity\timpossible\n#HttpOnly_127.0.0.1\tFALSE\t/\tFALSE\t0\tPHPSESSID\ttest-session\n"

	if err := os.WriteFile(file, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}

	session, err := readSession(file)

	if err != nil || session != "test-session" {
		t.Fatalf("session=%q err=%v", session, err)
	}

	if err := os.WriteFile(file, []byte(strings.ReplaceAll(contents, "127.0.0.1", "example.com")), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := readSession(file); err == nil {
		t.Fatal("принята cookie чужого домена")
	}
}

func TestWorkersSendConcurrentRequests(t *testing.T) {
	// Первый запрос не получит ответа, пока не начнётся второй.
	var entered atomic.Int32

	both := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if entered.Add(1) == 2 {
			close(both)
		}

		select {
		case <-both:
			fmt.Fprint(w, "Username and/or password incorrect.")

		case <-r.Context().Done():
		}
	}))

	defer server.Close()

	target := newDVWA("test-session", 2)
	target.endpoint = server.URL
	charset, _ := ResolveCharset("digits")
	cfg, _ := NewConfig(charset, 1, 1, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)

	defer cancel()

	value, err := search(ctx, cfg, target)

	if err != nil || value.Attempts != 10 {
		t.Fatalf("запросы не выполняются параллельно: %+v, %v", value, err)
	}
}

func TestHTTPErrorDiagnostics(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusFound, http.StatusServiceUnavailable} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html; charset=UTF-8")
				w.Header().Set("Location", "/login.php")
				w.Header().Set("Retry-After", "5")
				w.WriteHeader(status)
				fmt.Fprint(w, "<pre>Database error: Too many connections</pre>")
			}))

			defer server.Close()

			target := newDVWA("private-session-value", 1)
			target.endpoint = server.URL
			_, err := target.check(context.Background(), []byte("abc123"))

			if err == nil {
				t.Fatal("ожидалась ошибка")
			}

			for _, detail := range []string{"GET", "password=abc123", fmt.Sprint(status), "text/html", "Too many connections", "Retry-After: 5", "Location: /login.php"} {
				if !strings.Contains(err.Error(), detail) {
					t.Errorf("нет %q в ошибке: %v", detail, err)
				}
			}

			if strings.Contains(err.Error(), "private-session-value") {
				t.Error("в диагностике раскрыта cookie сессии")
			}
		})
	}
}

func TestErrorLogKeepsFullResponse(t *testing.T) {
	body := "<html>" + strings.Repeat("x", 2000) + "PHP Fatal error: database unavailable</html>"
	err := &responseError{&httpResponse{address: "http://127.0.0.1/test?password=abc", status: "200 OK", body: body}, "неожиданный ответ"}

	var console, journal strings.Builder

	writeError(&console, err, false)
	writeError(&journal, err, true)

	if !strings.Contains(console.String(), "ERROR:") || !strings.Contains(console.String(), "фрагмент") {
		t.Fatal("нет диагностики в терминале")
	}

	if strings.Contains(console.String(), "PHP Fatal error") {
		t.Fatal("в терминал попало полное длинное тело")
	}

	if !strings.Contains(journal.String(), body) {
		t.Fatal("журнал потерял конец HTTP-ответа")
	}
}

func TestSharedRequestPacing(t *testing.T) {
	requests := make(chan struct{}, 10)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- struct{}{}

		fmt.Fprint(w, "Username and/or password incorrect.")
	}))

	defer server.Close()

	target := newDVWA("test-session", 6)
	target.endpoint = server.URL
	ticks := make(chan time.Time)
	target.pace = ticks
	charset, _ := ResolveCharset("digits")
	cfg, _ := NewConfig(charset, 1, 1, 6)
	ctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	done := make(chan error, 1)

	go func() {
		_, err := search(ctx, cfg, target)

		done <- err
	}()

	for range 2 {
		select {
		case <-requests:
			t.Fatal("запрос отправлен без общего разрешения")

		case <-time.After(30 * time.Millisecond):
		}

		select {
		case ticks <- time.Now():

		case <-time.After(time.Second):
			t.Fatal("работники не ожидают таймер")
		}

		select {
		case <-requests:

		case <-time.After(time.Second):
			t.Fatal("разрешённый запрос не отправлен")
		}
	}

	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("ошибка отмены: %v", err)
		}

	case <-time.After(time.Second):
		t.Fatal("ожидание таймера не отменилось")
	}
}
