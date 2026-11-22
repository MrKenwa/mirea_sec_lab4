package app

import (
	"context"
	"errors"

	"protectedauth/internal/auth"
)

const DefaultUsername = "admin"
const DefaultPassword = "1234"

func ensureDefaultUser(ctx context.Context, service *auth.Service) error {
	err := service.CreateUser(ctx, DefaultUsername, DefaultPassword)
	if errors.Is(err, auth.ErrUserExists) {
		// Повторный запуск не меняет пароль, счётчик ошибок или блокировку.
		return nil
	}

	return err
}
