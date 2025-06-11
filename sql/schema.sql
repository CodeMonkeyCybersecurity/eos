-- /opt/schema.sql
-- 0644 stanley:stanley

-- ENUM types for state (Note: 'agent_status' removed to match provided d/agents output)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'alert_state') THEN
    CREATE TYPE alert_state AS ENUM ('new', 'summarized', 'sent', 'failed', 'archived');
  END IF;
END$$;


-- AGENTS TABLE: Source-of-truth for endpoints
CREATE TABLE IF NOT EXISTS agents (
  id          TEXT PRIMARY KEY,                         -- Wazuh agent ID
  name        TEXT,                                     -- Friendly name (NULLABLE as per d/agents)
  ip          TEXT,                                     -- Last known IP (NULLABLE as per d/agents)
  os          TEXT,                                     -- OS type (NULLABLE as per d/agents)
  registered  TIMESTAMPTZ,                              -- First seen (NULLABLE as per d/agents)
  last_seen   TIMESTAMPTZ DEFAULT now()                 -- Updated on each heartbeat/event (NULLABLE, with default, as per d/agents)
  -- Removed 'status' column and 'agent_status' ENUM to match d/agents output
);


-- ALERTS TABLE: Main event log, deduplication & audit trail
CREATE TABLE IF NOT EXISTS alerts (
  id                   BIGSERIAL PRIMARY KEY,
  alert_hash           TEXT UNIQUE NOT NULL,                  -- SHA-256 for deduplication
  agent_id             TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE, -- Source agent
  rule_id              INT NOT NULL,                          -- Wazuh/SIEM rule ID
  rule_level           INT NOT NULL,                          -- Wazuh/SIEM rule severity
  rule_desc            TEXT NOT NULL,                         -- Description of rule
  raw                  JSONB NOT NULL,                        -- Original JSON alert

  -- Pipeline/audit tracking
  ingest_timestamp     TIMESTAMPTZ DEFAULT now() NOT NULL,    -- Ingested to DB
  state                alert_state DEFAULT 'new' NOT NULL,    -- ENUM: workflow state

  -- LLM round-trip
  prompt_sent_at       TIMESTAMPTZ,                           -- LLM prompt send time (NULLABLE)
  prompt_text          TEXT,                                  -- Full LLM prompt text (NULLABLE)
  response_received_at TIMESTAMPTZ,                           -- LLM response received time (NULLABLE)
  response_text        TEXT,                                  -- Full LLM response (NULLABLE)

  -- New token columns added from d/alerts output
  prompt_tokens        INTEGER,                               -- Tokens used for prompt (NULLABLE)
  completion_tokens    INTEGER,                               -- Tokens used for completion (NULLABLE)
  total_tokens         INTEGER,                               -- Total tokens (NULLABLE)

  -- Notification/audit
  alert_sent_at        TIMESTAMPTZ,                           -- Outbound notification sent time (NULLABLE)
  alert_text           TEXT,                                  -- Formatted outbound alert (NULLABLE)

  -- Soft-delete/archive (optional)
  archived_at          TIMESTAMPTZ                            -- If set, alert is archived (NULLABLE)
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