package store

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

func Open(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("create database connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to database: %w", err)
	}

	return pool, nil
}

func CreateScan(
	ctx context.Context,
	pool *pgxpool.Pool,
	source string,
) (int64, error) {
	var scanID int64

	err := pool.QueryRow(
		ctx,
		`
			INSERT INTO scans (status, source)
			VALUES ($1, $2)
			RETURNING id
		`,
		"RUNNING",
		source,
	).Scan(&scanID)

	if err != nil {
		return 0, fmt.Errorf("create scan: %w", err)
	}

	return scanID, nil
}

func CompleteScan(
	ctx context.Context,
	pool *pgxpool.Pool,
	scanID int64,
) error {
	_, err := pool.Exec(
		ctx,
		`
			UPDATE scans
			SET status = $1,
			    completed_at = CURRENT_TIMESTAMP
			WHERE id = $2
		`,
		"COMPLETED",
		scanID,
	)

	if err != nil {
		return fmt.Errorf("complete scan: %w", err)
	}

	return nil
}
