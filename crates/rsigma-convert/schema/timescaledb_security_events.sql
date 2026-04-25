-- =============================================================================
-- Reference TimescaleDB Schema for Security Telemetry (OCSF-aligned)
-- =============================================================================
--
-- This schema is designed for a Lakewatch-style open SIEM backed by
-- PostgreSQL + TimescaleDB.  It stores normalized security events using
-- column names derived from the Open Cybersecurity Schema Framework (OCSF).
--
-- The `security_events` hypertable is the single landing table for all
-- event categories.  Category-specific fields that are NULL for unrelated
-- events are stored efficiently by TimescaleDB's columnar compression.
--
-- Usage:
--   psql -d siem -f timescaledb_security_events.sql
--
-- Prerequisites:
--   CREATE EXTENSION IF NOT EXISTS timescaledb;

-- ---------------------------------------------------------------------------
-- 1. Core hypertable
-- ---------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS security_events (
    -- Timestamp (partition key)
    time                      TIMESTAMPTZ NOT NULL,

    -- Event metadata
    event_id                  BIGINT,
    event_type                TEXT,
    category                  TEXT,         -- OCSF activity class: process, network, auth …
    severity                  SMALLINT,     -- 0=info, 1=low, 2=medium, 3=high, 4=critical
    rule_name                 TEXT,         -- Sigma rule title that matched (populated by eval)
    rule_id                   TEXT,         -- Sigma rule UUID

    -- Source host
    src_hostname              TEXT,
    src_ip                    INET,
    src_port                  INT,

    -- Destination host
    dst_hostname              TEXT,
    dst_ip                    INET,
    dst_port                  INT,

    -- Actor
    actor_user_name           TEXT,
    actor_user_domain         TEXT,
    subject_user_name         TEXT,
    subject_user_domain       TEXT,

    -- Process (OCSF process activity)
    process_pid               INT,
    process_file_path         TEXT,
    process_command_line      TEXT,
    process_original_name     TEXT,
    process_integrity_level   TEXT,
    process_file_hash         TEXT,
    process_current_directory TEXT,
    process_file_company      TEXT,
    process_file_description  TEXT,
    process_file_product      TEXT,
    process_file_version      TEXT,

    -- Parent process
    parent_process_pid        INT,
    parent_process_file_path  TEXT,
    parent_process_command_line TEXT,

    -- File activity
    file_path                 TEXT,

    -- Registry activity (Windows)
    registry_key              TEXT,
    registry_value            TEXT,

    -- DNS
    dns_query_name            TEXT,
    dns_answer                TEXT,
    dns_response_code         TEXT,

    -- Network
    network_protocol          TEXT,
    network_direction         TEXT,

    -- HTTP / Proxy
    http_url                  TEXT,
    http_user_agent           TEXT,
    http_method               TEXT,
    http_host                 TEXT,
    http_referrer             TEXT,
    http_status_code          INT,

    -- Authentication
    auth_logon_type           TEXT,
    auth_package              TEXT,

    -- Firewall / action
    action                    TEXT,

    -- Raw / overflow
    metadata                  JSONB,

    -- Full-text search (auto-populated by trigger or GENERATED column)
    search_vector             TSVECTOR
);

-- Convert to hypertable (idempotent: errors if already a hypertable)
SELECT create_hypertable(
    'security_events',
    by_range('time'),
    if_not_exists => TRUE
);

-- ---------------------------------------------------------------------------
-- 2. Indexes
-- ---------------------------------------------------------------------------

-- B-tree indexes for high-cardinality equality / range filters
CREATE INDEX IF NOT EXISTS idx_se_src_ip
    ON security_events (src_ip, time DESC);

CREATE INDEX IF NOT EXISTS idx_se_dst_ip
    ON security_events (dst_ip, time DESC);

CREATE INDEX IF NOT EXISTS idx_se_actor
    ON security_events (actor_user_name, time DESC);

CREATE INDEX IF NOT EXISTS idx_se_process_path
    ON security_events (process_file_path, time DESC);

CREATE INDEX IF NOT EXISTS idx_se_event_id
    ON security_events (event_id, time DESC);

CREATE INDEX IF NOT EXISTS idx_se_category
    ON security_events (category, time DESC);

CREATE INDEX IF NOT EXISTS idx_se_rule_name
    ON security_events (rule_name, time DESC);

CREATE INDEX IF NOT EXISTS idx_se_dns_query
    ON security_events (dns_query_name, time DESC);

-- GIN index for full-text search
CREATE INDEX IF NOT EXISTS idx_se_search_vector
    ON security_events USING GIN (search_vector);

-- GIN index for JSONB metadata queries
CREATE INDEX IF NOT EXISTS idx_se_metadata
    ON security_events USING GIN (metadata jsonb_path_ops);

-- ---------------------------------------------------------------------------
-- 3. Trigger: auto-populate search_vector
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION security_events_search_vector_update()
RETURNS trigger AS $$
BEGIN
    NEW.search_vector :=
        to_tsvector('simple', coalesce(NEW.process_command_line, '')) ||
        to_tsvector('simple', coalesce(NEW.process_file_path, ''))   ||
        to_tsvector('simple', coalesce(NEW.actor_user_name, ''))     ||
        to_tsvector('simple', coalesce(NEW.dns_query_name, ''))      ||
        to_tsvector('simple', coalesce(NEW.http_url, ''))            ||
        to_tsvector('simple', coalesce(NEW.file_path, ''))           ||
        to_tsvector('simple', coalesce(NEW.registry_key, ''));
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER trg_se_search_vector
    BEFORE INSERT OR UPDATE ON security_events
    FOR EACH ROW
    EXECUTE FUNCTION security_events_search_vector_update();

-- ---------------------------------------------------------------------------
-- 4. TimescaleDB compression policy
-- ---------------------------------------------------------------------------
-- Compress chunks older than 7 days.  Segmenting by category keeps queries
-- that filter on category fast even after compression.

ALTER TABLE security_events SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'category',
    timescaledb.compress_orderby = 'time DESC'
);

SELECT add_compression_policy(
    'security_events',
    compress_after => INTERVAL '7 days',
    if_not_exists => TRUE
);

-- ---------------------------------------------------------------------------
-- 5. Retention policy
-- ---------------------------------------------------------------------------
-- Drop chunks older than 90 days by default.  Adjust to match your
-- compliance requirements.

SELECT add_retention_policy(
    'security_events',
    drop_after => INTERVAL '90 days',
    if_not_exists => TRUE
);

-- ---------------------------------------------------------------------------
-- 6. Example continuous aggregate: hourly event counts by category
-- ---------------------------------------------------------------------------

CREATE MATERIALIZED VIEW IF NOT EXISTS security_events_hourly
WITH (timescaledb.continuous) AS
SELECT
    time_bucket('1 hour', time) AS bucket,
    category,
    rule_name,
    COUNT(*) AS event_count
FROM security_events
GROUP BY bucket, category, rule_name
WITH NO DATA;

SELECT add_continuous_aggregate_policy(
    'security_events_hourly',
    start_offset    => INTERVAL '3 hours',
    end_offset      => INTERVAL '1 hour',
    schedule_interval => INTERVAL '1 hour',
    if_not_exists => TRUE
);
