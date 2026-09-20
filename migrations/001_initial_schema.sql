CREATE TABLE scans (
    id BIGSERIAL PRIMARY KEY,
    started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,
    status TEXT NOT NULL CHECK (
        status IN ('RUNNING', 'COMPLETED', 'PARTIAL', 'FAILED')
    ),
    source TEXT NOT NULL,
    error_message TEXT
);

CREATE TABLE resources (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    cloud_resource_id TEXT NOT NULL,
    name TEXT NOT NULL,
    provider TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    raw_data JSONB NOT NULL DEFAULT '{}'::JSONB,
    UNIQUE (scan_id, cloud_resource_id)
);

CREATE TABLE check_results (
    id BIGSERIAL PRIMARY KEY,
    scan_id BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    resource_id BIGINT NOT NULL REFERENCES resources(id) ON DELETE CASCADE,
    check_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (
        status IN ('PASS', 'FAIL', 'UNKNOWN', 'NOT_APPLICABLE')
    ),
    severity TEXT NOT NULL CHECK (
        severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')
    ),
    message TEXT NOT NULL,
    evidence JSONB,
    UNIQUE (scan_id, resource_id, check_id)
);

CREATE INDEX idx_resources_scan_id
    ON resources(scan_id);

CREATE INDEX idx_check_results_scan_id
    ON check_results(scan_id);

CREATE INDEX idx_check_results_status
    ON check_results(status);

CREATE INDEX idx_check_results_check_id
    ON check_results(check_id);