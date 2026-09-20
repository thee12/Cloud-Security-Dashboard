package store

import (
	"context"
	"encoding/json"
	"fmt"

	"cloud-security-dashboard/internal/model"

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

func SaveScan(
	ctx context.Context,
	pool *pgxpool.Pool,
	source string,
	resources []model.Resource,
	results []model.CheckResult,
) (int64, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin transaction: %w", err)
	}

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	var scanID int64

	err = tx.QueryRow(
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

	resourceIDs := make(map[string]int64)

	for _, resource := range resources {
		rawData, err := json.Marshal(resource)
		if err != nil {
			return 0, fmt.Errorf(
				"encode resource %s: %w",
				resource.ID,
				err,
			)
		}

		var databaseResourceID int64

		err = tx.QueryRow(
			ctx,
			`
				INSERT INTO resources (
					scan_id,
					cloud_resource_id,
					name,
					provider,
					resource_type,
					raw_data
				)
				VALUES ($1, $2, $3, $4, $5, $6::jsonb)
				RETURNING id
			`,
			scanID,
			resource.ID,
			resource.Name,
			resource.Provider,
			resource.Type,
			rawData,
		).Scan(&databaseResourceID)

		if err != nil {
			return 0, fmt.Errorf(
				"save resource %s: %w",
				resource.ID,
				err,
			)
		}

		resourceIDs[resource.ID] = databaseResourceID
	}

	for _, result := range results {
		databaseResourceID, found := resourceIDs[result.ResourceID]
		if !found {
			return 0, fmt.Errorf(
				"result references unknown resource %s",
				result.ResourceID,
			)
		}

		var evidenceJSON []byte

		if result.Evidence != nil {
			evidenceJSON, err = json.Marshal(result.Evidence)
			if err != nil {
				return 0, fmt.Errorf(
					"encode evidence for %s: %w",
					result.CheckID,
					err,
				)
			}
		}

		_, err = tx.Exec(
			ctx,
			`
				INSERT INTO check_results (
					scan_id,
					resource_id,
					check_id,
					status,
					severity,
					message,
					evidence
				)
				VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
			`,
			scanID,
			databaseResourceID,
			result.CheckID,
			result.Status,
			result.Severity,
			result.Message,
			evidenceJSON,
		)

		if err != nil {
			return 0, fmt.Errorf(
				"save result %s for %s: %w",
				result.CheckID,
				result.ResourceID,
				err,
			)
		}
	}

	_, err = tx.Exec(
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
		return 0, fmt.Errorf("complete scan: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit scan transaction: %w", err)
	}

	return scanID, nil
}
