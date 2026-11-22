// Package auth содержит правила авторизации и контракты её зависимостей.
package auth

import (
	"context"
	"errors"
	"time"
)

const MaxFailures = 5
const IPLimit = 20
const IPWindow = time.Minute

type Result string

const (
	Success            Result = "success"
	InvalidCredentials Result = "invalid"
	AccountLocked      Result = "locked"
)

var ErrUserNotFound = errors.New("пользователь не найден")
var ErrUserExists = errors.New("пользователь уже существует")

type User struct {
	Username string
	Salt     []byte
	Hash     []byte
	Failures int
	Locked   bool
}

// UpdateUser выполняет callback и сохраняет счётчик ошибок и блокировку
// в одной транзакции.
// Репозиторий должен исключить конкурентное чтение устаревшего счётчика.
type UserRepository interface {
	CreateUser(context.Context, User) error
	UpdateUser(context.Context, string, func(*User) error) error
}

type AttemptRepository interface {
	RegisterIPAttempt(context.Context, string, time.Time, time.Duration, int) (int, error)
}

type PasswordHasher interface {
	Hash(string) (salt, hash []byte)
	Verify(string, []byte, []byte) bool
}

type Service struct {
	users     UserRepository
	attempts  AttemptRepository
	passwords PasswordHasher
	dummySalt []byte
	dummyHash []byte
}

func NewService(users UserRepository, attempts AttemptRepository, passwords PasswordHasher) *Service {
	salt, hash := passwords.Hash("nonexistent-user")

	return &Service{
		users:     users,
		attempts:  attempts,
		passwords: passwords,
		dummySalt: salt,
		dummyHash: hash,
	}
}

func (s *Service) CreateUser(ctx context.Context, username, password string) error {
	if len(username) < 1 || len(username) > 64 || len(password) < 1 || len(password) > 1024 {
		return errors.New("логин: 1–64 байта, пароль: 1–1024 байта")
	}

	salt, hash := s.passwords.Hash(password)

	return s.users.CreateUser(ctx, User{
		Username: username,
		Salt:     salt,
		Hash:     hash,
	})
}

func (s *Service) Unlock(ctx context.Context, username string) error {
	return s.users.UpdateUser(ctx, username, func(user *User) error {
		user.Failures = 0
		user.Locked = false

		return nil
	})
}

func (s *Service) Authenticate(ctx context.Context, username, password string) (Result, error) {
	result := InvalidCredentials

	err := s.users.UpdateUser(ctx, username, func(user *User) error {
		if len(user.Salt) != 16 || len(user.Hash) != 32 ||
			user.Failures < 0 || user.Failures > MaxFailures || user.Locked != (user.Failures >= MaxFailures) {
			return errors.New("повреждённая учётная запись")
		}

		if user.Locked {
			result = AccountLocked

			return nil
		}

		if s.passwords.Verify(password, user.Salt, user.Hash) {
			user.Failures = 0
			result = Success

			return nil
		}

		user.Failures++
		user.Locked = user.Failures >= MaxFailures

		if user.Locked {
			result = AccountLocked
		}

		return nil
	})

	if errors.Is(err, ErrUserNotFound) {
		// Неизвестный логин тоже проходит затратную проверку хеша.
		_ = s.passwords.Verify(password, s.dummySalt, s.dummyHash)

		return InvalidCredentials, nil
	}

	if err != nil {
		return "", err
	}

	return result, nil
}

func (s *Service) AllowIP(ctx context.Context, ip string, now time.Time) (int, error) {
	return s.attempts.RegisterIPAttempt(ctx, ip, now, IPWindow, IPLimit)
}
