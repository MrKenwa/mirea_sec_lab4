package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"

	"protectedauth/internal/auth"
)

func (s *Store) CreateUser(ctx context.Context, user auth.User) error {
	_, err := s.db.ExecContext(ctx,
		"INSERT INTO users (username, salt, password_hash) VALUES (?, ?, ?)",
		user.Username, user.Salt, user.Hash,
	)

	var sqliteError *sqlite.Error
	if errors.As(err, &sqliteError) && sqliteError.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY {
		return auth.ErrUserExists
	}

	return err
}

// UpdateUser оставляет SQL-транзакцию открытой на время callback сервиса.
// BEGIN IMMEDIATE исключает потерю обновлений при параллельной авторизации.
func (s *Store) UpdateUser(ctx context.Context, username string, update func(*auth.User) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	user := auth.User{Username: username}
	err = tx.QueryRowContext(ctx,
		"SELECT salt, password_hash, failures, locked FROM users WHERE username = ?",
		username,
	).Scan(&user.Salt, &user.Hash, &user.Failures, &user.Locked)

	if errors.Is(err, sql.ErrNoRows) {
		return auth.ErrUserNotFound
	}

	if err != nil {
		return err
	}

	if err := update(&user); err != nil {
		return err
	}

	if _, err := tx.ExecContext(ctx,
		"UPDATE users SET failures = ?, locked = ? WHERE username = ?",
		user.Failures, user.Locked, username,
	); err != nil {
		return err
	}

	return tx.Commit()
}
