package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (s *Store) RegisterIPAttempt(ctx context.Context, ip string, now time.Time, window time.Duration, limit int) (int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, "DELETE FROM ip_limits WHERE started <= ?", now.Add(-window).UnixNano()); err != nil {
		return 0, err
	}

	var started int64
	var attempts int
	err = tx.QueryRowContext(ctx, "SELECT started, attempts FROM ip_limits WHERE ip = ?", ip).Scan(&started, &attempts)

	if errors.Is(err, sql.ErrNoRows) {
		if _, err := tx.ExecContext(ctx, "INSERT INTO ip_limits (ip, started, attempts) VALUES (?, ?, 1)", ip, now.UnixNano()); err != nil {
			return 0, err
		}

		return 0, tx.Commit()
	}

	if err != nil {
		return 0, err
	}

	if attempts >= limit {
		retry := int(time.Unix(0, started).Add(window).Sub(now).Seconds()) + 1
		if retry < 1 {
			retry = 1
		}

		return retry, tx.Commit()
	}

	if _, err := tx.ExecContext(ctx, "UPDATE ip_limits SET attempts = attempts + 1 WHERE ip = ?", ip); err != nil {
		return 0, err
	}

	return 0, tx.Commit()
}
