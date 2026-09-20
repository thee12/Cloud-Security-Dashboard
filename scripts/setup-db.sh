#!/usr/bin/env bash

set -euo pipefail

project_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$project_dir"

if [[ ! -f ".env" ]]; then
    echo "Missing .env file."
    echo "Copy .env.example to .env and configure the local values."
    exit 1
fi

set -a
source .env
set +a

echo "Starting PostgreSQL..."
docker compose up -d db

echo "Waiting for PostgreSQL..."

database_ready=0

for attempt in $(seq 1 30); do
    if docker compose exec -T db \
        pg_isready \
        -U "$POSTGRES_USER" \
        -d "$POSTGRES_DB" > /dev/null 2>&1; then
        database_ready=1
        break
    fi

    sleep 1
done

if [[ "$database_ready" -ne 1 ]]; then
    echo "PostgreSQL did not become ready."
    docker compose logs db
    exit 1
fi

echo "Applying database migration..."

docker compose exec -T db \
    psql \
    -v ON_ERROR_STOP=1 \
    -U "$POSTGRES_USER" \
    -d "$POSTGRES_DB" \
    < migrations/001_initial_schema.sql

echo "Database setup complete."