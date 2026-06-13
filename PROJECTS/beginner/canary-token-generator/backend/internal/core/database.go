// ©AngelaMos | 2026
// database.go

package core

import (
	"context"
	crand "crypto/rand"
	"database/sql"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/config"
)

type Database struct {
	DB *sqlx.DB
}

func (d *Database) SQLDB() *sql.DB {
	return d.DB.DB
}

func NewDatabase(
	ctx context.Context,
	cfg config.DatabaseConfig,
) (*Database, error) {
	db, err := sqlx.ConnectContext(ctx, "pgx", cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("connect to database: %w", err)
	}

	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(jitteredDuration(cfg.ConnMaxLifetime))
	db.SetConnMaxIdleTime(cfg.ConnMaxIdleTime)

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if pingErr := db.PingContext(pingCtx); pingErr != nil {
		if closeErr := db.Close(); closeErr != nil {
			return nil, fmt.Errorf(
				"ping database: %w (close also failed: %w)",
				pingErr,
				closeErr,
			)
		}
		return nil, fmt.Errorf("ping database: %w", pingErr)
	}

	return &Database{DB: db}, nil
}

func (d *Database) Close() error {
	if d.DB != nil {
		return d.DB.Close()
	}
	return nil
}

func (d *Database) Ping(ctx context.Context) error {
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := d.DB.PingContext(pingCtx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	return nil
}

func (d *Database) Stats() sql.DBStats {
	return d.DB.Stats()
}

type DBTX interface {
	sqlx.ExtContext
	sqlx.ExecerContext
	GetContext(ctx context.Context, dest any, query string, args ...any) error
	SelectContext(
		ctx context.Context,
		dest any,
		query string,
		args ...any,
	) error
}

func InTx(ctx context.Context, db *sqlx.DB, fn func(tx *sqlx.Tx) error) error {
	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				slog.Error(
					"rollback failed during panic recovery",
					"error", rbErr,
				)
			}
			panic(p)
		}
	}()

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("rollback failed: %w (original: %w)", rbErr, err)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

func InTxWithOptions(
	ctx context.Context,
	db *sqlx.DB,
	opts *sql.TxOptions,
	fn func(tx *sqlx.Tx) error,
) error {
	tx, err := db.BeginTxx(ctx, opts)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				slog.Error(
					"rollback failed during panic recovery",
					"error", rbErr,
				)
			}
			panic(p)
		}
	}()

	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback(); rbErr != nil {
			return fmt.Errorf("rollback failed: %w (original: %w)", rbErr, err)
		}
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}

	return nil
}

func jitteredDuration(base time.Duration) time.Duration {
	maxJitter := int64(base / 7)
	if maxJitter <= 0 {
		return base
	}
	jitter, err := crand.Int(crand.Reader, big.NewInt(maxJitter))
	if err != nil {
		return base
	}
	return base + time.Duration(jitter.Int64())
}
