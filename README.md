# Cloud Security Compliance Dashboard

An in-progress cloud security assessment platform that inventories cloud
resources, evaluates configuration risks, stores historical results, and
provides evidence for remediation.

The current version uses local JSON fixtures. Live Azure collection has not
been implemented yet.

## Current capabilities

- Reads normalized cloud resources from JSON
- Detects public inbound RDP access on port 3389
- Detects public inbound SSH access on port 22
- Produces PASS, FAIL, and UNKNOWN results
- Includes evidence explaining failed checks
- Stores scans, resource snapshots, and results in PostgreSQL
- Supports baseline and remediated fixture scenarios
- Includes automated Go tests

## Technology

- Go
- PostgreSQL
- Docker Compose
- Azure CLI
- React and TypeScript planned for the dashboard

## Project structure

```text
cmd/scanner/        Scanner command
internal/checks/    Security check logic
internal/model/     Shared data models
internal/store/     PostgreSQL storage
fixtures/           Sample resource data
migrations/         Database schema
scripts/            Local setup scripts
docs/               Project documentation