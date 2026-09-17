CREATE EXTENSION IF NOT EXISTS timescaledb;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS tenants (
    id    TEXT PRIMARY KEY,
    data  JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id    TEXT PRIMARY KEY,
    data  JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users ((data->>'tenant_id'));
CREATE INDEX IF NOT EXISTS idx_users_email ON users ((data->>'email'));

CREATE TABLE IF NOT EXISTS plants (
    id    TEXT PRIMARY KEY,
    data  JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_plants_tenant ON plants ((data->>'tenant_id'));

CREATE TABLE IF NOT EXISTS areas (
    id    TEXT PRIMARY KEY,
    data  JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_areas_tenant ON areas ((data->>'tenant_id'));
CREATE INDEX IF NOT EXISTS idx_areas_plant ON areas ((data->>'plant_id'));

CREATE TABLE IF NOT EXISTS lines (
    id    TEXT PRIMARY KEY,
    data  JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lines_tenant ON lines ((data->>'tenant_id'));

CREATE TABLE IF NOT EXISTS assets (
    id    TEXT PRIMARY KEY,
    data  JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_assets_tenant ON assets ((data->>'tenant_id'));
CREATE INDEX IF NOT EXISTS idx_assets_code ON assets ((data->>'asset_code'));
CREATE INDEX IF NOT EXISTS idx_assets_plant ON assets ((data->>'plant_id'));

CREATE TABLE IF NOT EXISTS alarms (
    id    TEXT PRIMARY KEY,
    data  JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alarms_tenant ON alarms ((data->>'tenant_id'));
CREATE INDEX IF NOT EXISTS idx_alarms_asset ON alarms ((data->>'asset_id'));
CREATE INDEX IF NOT EXISTS idx_alarms_created ON alarms ((data->>'created_at'));

CREATE TABLE IF NOT EXISTS maintenance_records (
    id    TEXT PRIMARY KEY,
    data  JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_maint_tenant ON maintenance_records ((data->>'tenant_id'));
CREATE INDEX IF NOT EXISTS idx_maint_asset ON maintenance_records ((data->>'asset_id'));

CREATE TABLE IF NOT EXISTS downtime_events (
    id    TEXT PRIMARY KEY,
    data  JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_downtime_tenant ON downtime_events ((data->>'tenant_id'));
CREATE INDEX IF NOT EXISTS idx_downtime_asset ON downtime_events ((data->>'asset_id'));

CREATE TABLE IF NOT EXISTS energy_records (
    id    TEXT PRIMARY KEY,
    data  JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_energy_tenant ON energy_records ((data->>'tenant_id'));

CREATE TABLE IF NOT EXISTS production_log (
    id    TEXT PRIMARY KEY,
    data  JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_prodlog_tenant ON production_log ((data->>'tenant_id'));
CREATE INDEX IF NOT EXISTS idx_prodlog_date ON production_log ((data->>'date'));

CREATE TABLE IF NOT EXISTS escalations (
    id    TEXT PRIMARY KEY,
    data  JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_escalations_tenant ON escalations ((data->>'tenant_id'));

CREATE TABLE IF NOT EXISTS audit_logs (
    id    TEXT PRIMARY KEY,
    data  JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_logs ((data->>'tenant_id'));

CREATE TABLE IF NOT EXISTS report_templates (
    id    TEXT PRIMARY KEY,
    data  JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_reporttpl_tenant ON report_templates ((data->>'tenant_id'));

CREATE TABLE IF NOT EXISTS tenant_modules (
    id    TEXT PRIMARY KEY,
    data  JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tenantmod_tenant ON tenant_modules ((data->>'tenant_id'));

CREATE TABLE IF NOT EXISTS telemetry (
    ts                TIMESTAMPTZ NOT NULL,
    asset_id          TEXT NOT NULL,
    tenant_id         TEXT NOT NULL,
    asset_code        TEXT,
    machine_status    TEXT,
    temperature       DOUBLE PRECISION,
    vibration         DOUBLE PRECISION,
    pressure          DOUBLE PRECISION,
    rpm               DOUBLE PRECISION,
    voltage           DOUBLE PRECISION,
    current           DOUBLE PRECISION,
    flow              DOUBLE PRECISION,
    power             DOUBLE PRECISION,
    energy            DOUBLE PRECISION,
    production_count  INTEGER,
    good_count        INTEGER,
    reject_count      INTEGER,
    alarm             BOOLEAN,
    alarm_message     TEXT
);

SELECT create_hypertable('telemetry', 'ts', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_telemetry_asset_ts ON telemetry (asset_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_tenant ON telemetry (tenant_id, ts DESC);