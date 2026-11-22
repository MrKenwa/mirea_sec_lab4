// Package app собирает зависимости, запускает сервер и выполняет разблокировку.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"protectedauth/internal/auth"
	"protectedauth/internal/httpserver"
	"protectedauth/internal/password"
	"protectedauth/internal/session"
	"protectedauth/internal/storage/sqlite"
)

const address = "127.0.0.1:4281"
const databasePath = "data/auth.sqlite3"

func Run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) > 1 || len(args) == 1 && args[0] != "unlock" {
		return errors.New("использование: go run . [unlock]")
	}

	store, err := sqlite.Open(databasePath)
	if err != nil {
		return err
	}
	defer store.Close()

	service := auth.NewService(store, store, password.Argon2id{})

	if len(args) == 1 {
		if err := service.Unlock(ctx, DefaultUsername); err != nil {
			return err
		}

		_, err := fmt.Fprintln(out, "Блокировка admin снята")

		return err
	}

	if err := ensureDefaultUser(ctx, service); err != nil {
		return err
	}

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()

	if _, err := fmt.Fprintf(out, "Форма: http://%s%s\n", address, httpserver.LoginPath); err != nil {
		return err
	}

	handler := httpserver.New(service, session.NewManager(time.Now), time.Now)

	return serve(ctx, listener, handler)
}
