// Package sqlite реализует хранение пользователей и лимитов через database/sql.
package sqlite

import (
	"bytes"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

const schemaVersion = 2

//go:embed schema.sql
var schema string

type Store struct {
	path string
	db   *sql.DB
}

func Open(path string) (*Store, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}

	// Создаём файл с закрытыми правами до открытия драйвером SQLite.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}

	var header [16]byte
	n, readErr := file.Read(header[:])
	closeErr := file.Close()

	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, readErr
	}

	if closeErr != nil {
		return nil, closeErr
	}

	if n > 0 && string(header[:n]) != "SQLite format 3\x00" {
		if bytes.HasPrefix(bytes.TrimSpace(header[:n]), []byte("{")) {
			return nil, errors.New("ожидалась SQLite-база, получен JSON: используйте новый путь -data; исходный файл сохранён")
		}

		return nil, errors.New("файл не является SQLite-базой")
	}

	if err := os.Chmod(path, 0600); err != nil {
		return nil, err
	}

	query := url.Values{}
	query.Add("_pragma", "busy_timeout(5000)")
	query.Add("_pragma", "journal_mode(WAL)")
	query.Set("_txlock", "immediate")

	address := url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: query.Encode()}
	db, err := sql.Open("sqlite", address.String())
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	s := &Store{path: path, db: db}
	if err := s.initialize(); err != nil {
		s.Close()

		return nil, fmt.Errorf("не удалось открыть SQLite: %w", err)
	}

	return s, nil
}

func (s *Store) initialize() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var version int
	if err := tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}

	if version != 0 && version != 1 && version != schemaVersion {
		return fmt.Errorf("неподдерживаемая версия SQLite-схемы: %d", version)
	}

	if version == 1 {
		// Старый формат использовал только Argon2id. Удаляем избыточное поле,
		// сохраняя хеши, соли, счётчики ошибок и блокировки.
		if _, err := tx.Exec("ALTER TABLE users DROP COLUMN algorithm"); err != nil {
			return fmt.Errorf("миграция SQLite v1 -> v2: %w", err)
		}
	}

	if _, err := tx.Exec(schema); err != nil {
		return err
	}

	if _, err := tx.Exec("PRAGMA user_version = 2"); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *Store) Close() error {
	return s.db.Close()
}
