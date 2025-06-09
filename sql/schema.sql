-- /opt/schema.sql
-- 0644 stanley:stanley


-- ENUM types for status and state
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'agent_status') THEN
    CREATE TYPE agent_status AS ENUM ('active', 'inactive', 'retired');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'alert_state') THEN
    CREATE TYPE alert_state AS ENUM ('new', 'summarized', 'sent', 'failed', 'archived');
  END IF;
END$$;


-- AGENTS TABLE: Source-of-truth for endpoints
CREATE TABLE IF NOT EXISTS agents (
  id          TEXT PRIMARY KEY,                       -- Wazuh agent ID, hostname, or UUID
  name        TEXT NOT NULL,                          -- Friendly name
  ip          TEXT NOT NULL,                          -- Last known IP
  os          TEXT,                                   -- OS type
  registered  TIMESTAMPTZ DEFAULT now() NOT NULL,     -- First seen
  last_seen   TIMESTAMPTZ DEFAULT now() NOT NULL,     -- Updated on each heartbeat/event
  status      agent_status DEFAULT 'active' NOT NULL  -- ENUM: active/inactive/retired
);


-- ALERTS TABLE: Main event log, deduplication & audit trail
CREATE TABLE IF NOT EXISTS alerts (
  id                   BIGSERIAL PRIMARY KEY,
  alert_hash           TEXT UNIQUE NOT NULL,   -- SHA-256 for deduplication
  agent_id             TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE, -- Source agent
  rule_id              INT NOT NULL,           -- Wazuh/SIEM rule ID
  rule_level           INT NOT NULL,           -- Wazuh/SIEM rule severity
  rule_desc            TEXT NOT NULL,          -- Description of rule
  raw                  JSONB NOT NULL,         -- Original JSON alert


  -- Pipeline/audit tracking
  ingest_timestamp     TIMESTAMPTZ DEFAULT now() NOT NULL,   -- Ingested to DB
  state                alert_state DEFAULT 'new' NOT NULL,   -- ENUM: workflow state


  -- LLM round-trip
  prompt_sent_at       TIMESTAMPTZ,          -- LLM prompt send time
  prompt_text          TEXT,                 -- Full LLM prompt text
  response_received_at TIMESTAMPTZ,          -- LLM response received time
  response_text        TEXT,                 -- Full LLM response


  -- Notification/audit
  alert_sent_at        TIMESTAMPTZ,          -- Outbound notification sent time
  alert_text           TEXT,                 -- Formatted outbound alert


  -- Soft-delete/archive (optional)
  archived_at          TIMESTAMPTZ           -- If set, alert is archived
);


-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_alerts_agent_id ON alerts(agent_id);
CREATE INDEX IF NOT EXISTS idx_alerts_ingest_timestamp ON alerts(ingest_timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_state ON alerts(state);


-- Notify on NEW alert (after insert)
CREATE OR REPLACE FUNCTION trg_alert_new_notify()
  RETURNS trigger AS $$
BEGIN
  PERFORM pg_notify('new_alert', NEW.id::text);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- Notify when an alert receives a new LLM response
CREATE OR REPLACE FUNCTION trg_alert_response_notify()
  RETURNS trigger AS $$
BEGIN
  IF (OLD.response_text IS NULL AND NEW.response_text IS NOT NULL) THEN
    PERFORM pg_notify('new_response', NEW.id::text);
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- Notify when an alert notification is sent
CREATE OR REPLACE FUNCTION trg_alert_sent_notify()
  RETURNS trigger AS $$
BEGIN
  IF (OLD.alert_text IS NULL AND NEW.alert_text IS NOT NULL) THEN
    PERFORM pg_notify('alert_sent', NEW.id::text);
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- Idempotent trigger creation
DO $$
BEGIN
  -- After insert: new alert
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'trg_alert_new_notify'
  ) THEN
    CREATE TRIGGER trg_alert_new_notify
      AFTER INSERT ON alerts
      FOR EACH ROW EXECUTE FUNCTION trg_alert_new_notify();
  END IF;


  -- After update: new LLM response
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'trg_alert_response_notify'
  ) THEN
    CREATE TRIGGER trg_alert_response_notify
      AFTER UPDATE OF response_text ON alerts
      FOR EACH ROW EXECUTE FUNCTION trg_alert_response_notify();
  END IF;


  -- After update: outbound alert sent
  IF NOT EXISTS (
    SELECT 1 FROM pg_trigger WHERE tgname = 'trg_alert_sent_notify'
  ) THEN
    CREATE TRIGGER trg_alert_sent_notify
      AFTER UPDATE OF alert_text ON alerts
      FOR EACH ROW EXECUTE FUNCTION trg_alert_sent_notify();
  END IF;
END;
$$;


-- Optional: Example comment for collaborators
COMMENT ON TABLE agents IS 'Source-of-truth for endpoint metadata';
COMMENT ON TABLE alerts IS 'Security event pipeline: deduplicated, auditable, LLM-enriched, and user notification tracked.';
COMMENT ON COLUMN alerts.archived_at IS 'Set if/when alert is logically archived (soft delete or for partitioning).';