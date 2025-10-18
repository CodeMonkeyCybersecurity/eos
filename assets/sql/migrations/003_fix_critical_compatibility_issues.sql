-- Migration: Fix Critical Compatibility Issues
-- Description: Comprehensive fix for schema/code compatibility issues
-- Date: 2025-06-25
-- Author: DevSecOps Pipeline - Critical Bug Fix
-- Priority: URGENT - Required for pipeline functionality

BEGIN;

-- ═══════════════════════════════════════════════════════════════════════════════
-- CRITICAL FIX #1: Alert State Enum Mismatch
-- ═══════════════════════════════════════════════════════════════════════════════

-- Drop existing triggers that reference the old enum
DROP TRIGGER IF EXISTS trg_alert_new_notify ON alerts;
DROP TRIGGER IF EXISTS trg_alert_response_notify ON alerts;
DROP TRIGGER IF EXISTS trg_alert_sent_notify ON alerts;

-- Safely add missing enum values to existing alert_state type
DO $$ 
BEGIN
    -- Add 'agent_enriched' state
    IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'agent_enriched' AND enumtypid = 'alert_state'::regtype) THEN
        ALTER TYPE alert_state ADD VALUE 'agent_enriched' AFTER 'new';
    END IF;
    
    -- Add 'structured' state  
    IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'structured' AND enumtypid = 'alert_state'::regtype) THEN
        ALTER TYPE alert_state ADD VALUE 'structured' AFTER 'summarized';
    END IF;
    
    -- Add 'formatted' state
    IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'formatted' AND enumtypid = 'alert_state'::regtype) THEN
        ALTER TYPE alert_state ADD VALUE 'formatted' AFTER 'structured';
    END IF;
END $$;

-- ═══════════════════════════════════════════════════════════════════════════════
-- CRITICAL FIX #2: Missing Database Columns
-- ═══════════════════════════════════════════════════════════════════════════════

-- Add missing timestamp columns for pipeline stages
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS agent_enriched_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS structured_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS formatted_at TIMESTAMP WITH TIME ZONE;

-- Add missing prompt tracking columns (ensure they exist)
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS prompt_type VARCHAR(100);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS prompt_template TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS parser_used VARCHAR(100);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS parser_success BOOLEAN DEFAULT TRUE;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS parser_error TEXT;
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS parser_duration_ms INTEGER;

-- ═══════════════════════════════════════════════════════════════════════════════
-- CRITICAL FIX #3: Standardized Notification Functions
-- ═══════════════════════════════════════════════════════════════════════════════

-- Function for new alert notifications
CREATE OR REPLACE FUNCTION trg_alert_new_notify()
  RETURNS trigger AS $$
BEGIN
  PERFORM pg_notify('new_alert', NEW.id::text);
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function for agent enriched notifications  
CREATE OR REPLACE FUNCTION trg_alert_agent_enriched_notify()
  RETURNS trigger AS $$
BEGIN
  IF (NEW.state = 'agent_enriched' AND (OLD.state IS NULL OR OLD.state != 'agent_enriched')) THEN
    PERFORM pg_notify('agent_enriched', NEW.id::text);
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function for LLM response notifications
CREATE OR REPLACE FUNCTION trg_alert_response_notify()
  RETURNS trigger AS $$
BEGIN
  IF (OLD.response_text IS NULL AND NEW.response_text IS NOT NULL) THEN
    PERFORM pg_notify('new_response', NEW.id::text);
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function for structured alert notifications
CREATE OR REPLACE FUNCTION trg_alert_structured_notify()
  RETURNS trigger AS $$
BEGIN
  IF (NEW.state = 'structured' AND (OLD.state IS NULL OR OLD.state != 'structured')) THEN
    PERFORM pg_notify('alert_structured', NEW.id::text);
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function for formatted alert notifications
CREATE OR REPLACE FUNCTION trg_alert_formatted_notify()
  RETURNS trigger AS $$
BEGIN
  IF (NEW.state = 'formatted' AND (OLD.state IS NULL OR OLD.state != 'formatted')) THEN
    PERFORM pg_notify('alert_formatted', NEW.id::text);
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Function for sent alert notifications (final stage)
CREATE OR REPLACE FUNCTION trg_alert_sent_notify()
  RETURNS trigger AS $$
BEGIN
  IF (NEW.state = 'sent' AND (OLD.state IS NULL OR OLD.state != 'sent')) THEN
    PERFORM pg_notify('alert_sent', NEW.id::text);
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ═══════════════════════════════════════════════════════════════════════════════
-- CRITICAL FIX #4: Recreate All Triggers with Proper Channels
-- ═══════════════════════════════════════════════════════════════════════════════

-- Trigger for new alerts (after insert)
CREATE TRIGGER trg_alert_new_notify
  AFTER INSERT ON alerts
  FOR EACH ROW EXECUTE FUNCTION trg_alert_new_notify();

-- Trigger for state changes (after update)
CREATE TRIGGER trg_alert_state_notify
  AFTER UPDATE OF state ON alerts
  FOR EACH ROW EXECUTE FUNCTION trg_alert_agent_enriched_notify();

CREATE TRIGGER trg_alert_state_structured_notify
  AFTER UPDATE OF state ON alerts
  FOR EACH ROW EXECUTE FUNCTION trg_alert_structured_notify();

CREATE TRIGGER trg_alert_state_formatted_notify
  AFTER UPDATE OF state ON alerts
  FOR EACH ROW EXECUTE FUNCTION trg_alert_formatted_notify();

CREATE TRIGGER trg_alert_state_sent_notify
  AFTER UPDATE OF state ON alerts
  FOR EACH ROW EXECUTE FUNCTION trg_alert_sent_notify();

-- Trigger for LLM response (after response_text update)
CREATE TRIGGER trg_alert_response_notify
  AFTER UPDATE OF response_text ON alerts
  FOR EACH ROW EXECUTE FUNCTION trg_alert_response_notify();

-- ═══════════════════════════════════════════════════════════════════════════════
-- MEDIUM FIX #1: Ensure parser_metrics Table Exists with Correct Schema
-- ═══════════════════════════════════════════════════════════════════════════════

-- Create parser_metrics table with correct data types
CREATE TABLE IF NOT EXISTS parser_metrics (
    id SERIAL PRIMARY KEY,
    alert_id INTEGER REFERENCES alerts(id),
    prompt_type VARCHAR(100) NOT NULL,
    parser_used VARCHAR(100) NOT NULL,
    success BOOLEAN NOT NULL,
    parse_time_ms INTEGER NOT NULL,  -- Standardized as INTEGER
    sections_extracted INTEGER DEFAULT 0,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Fix data type if table already exists with wrong type
DO $$
BEGIN
    -- Check if parse_time_ms is FLOAT and convert to INTEGER
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'parser_metrics' 
        AND column_name = 'parse_time_ms' 
        AND data_type = 'double precision'
    ) THEN
        ALTER TABLE parser_metrics ALTER COLUMN parse_time_ms TYPE INTEGER;
    END IF;
END $$;

-- ═══════════════════════════════════════════════════════════════════════════════
-- MEDIUM FIX #2: Create Missing Database Views and Functions
-- ═══════════════════════════════════════════════════════════════════════════════

-- Enhanced parser performance view
CREATE OR REPLACE VIEW parser_performance AS
SELECT 
    prompt_type,
    parser_used,
    COUNT(*) as total_attempts,
    SUM(CASE WHEN success THEN 1 ELSE 0 END) as successful_parses,
    ROUND(
        (SUM(CASE WHEN success THEN 1 ELSE 0 END)::decimal / COUNT(*)) * 100, 
        2
    ) as success_rate_percent,
    ROUND(AVG(parse_time_ms) FILTER (WHERE success), 2) as avg_parse_time_ms,
    MAX(parse_time_ms) as max_parse_time_ms,
    AVG(sections_extracted) as avg_sections_extracted,
    COUNT(CASE WHEN NOT success THEN 1 END) as failure_count,
    MAX(created_at) as last_attempt
FROM parser_metrics
WHERE created_at > NOW() - INTERVAL '7 days'
GROUP BY prompt_type, parser_used
ORDER BY prompt_type, success_rate_percent DESC;

-- Prompt usage statistics view
CREATE OR REPLACE VIEW prompt_usage_stats AS
SELECT 
    prompt_type,
    COUNT(*) as total_alerts,
    COUNT(CASE WHEN state = 'sent' THEN 1 END) as successfully_sent,
    COUNT(CASE WHEN parser_success = FALSE THEN 1 END) as parser_failures,
    ROUND(
        (COUNT(CASE WHEN state = 'sent' THEN 1 END)::decimal / COUNT(*)) * 100, 
        2
    ) as end_to_end_success_rate,
    AVG(parser_duration_ms) as avg_parser_duration_ms,
    MIN(ingest_timestamp) as first_used,
    MAX(ingest_timestamp) as last_used
FROM alerts
WHERE prompt_type IS NOT NULL 
  AND ingest_timestamp > NOW() - INTERVAL '7 days'
GROUP BY prompt_type
ORDER BY total_alerts DESC;

-- Comprehensive pipeline status view
CREATE OR REPLACE VIEW alert_processing_status AS
SELECT 
    id,
    alert_hash,
    agent_id,
    rule_level,
    state,
    prompt_type,
    parser_used,
    parser_success,
    ingest_timestamp as created_at,
    agent_enriched_at,
    response_received_at,
    structured_at,
    formatted_at,
    alert_sent_at as sent_at,
    CASE 
        WHEN state = 'sent' THEN 'Complete'
        WHEN state = 'formatted' THEN 'Ready for Sending'
        WHEN state = 'structured' THEN 'Ready for Formatting'
        WHEN state = 'summarized' THEN 'Ready for Structuring'
        WHEN state = 'agent_enriched' THEN 'Ready for LLM Analysis'
        WHEN state = 'new' THEN 'Ready for Agent Enrichment'
        ELSE 'Processing'
    END as processing_stage,
    -- Calculate processing durations
    CASE 
        WHEN agent_enriched_at IS NOT NULL AND ingest_timestamp IS NOT NULL 
        THEN EXTRACT(EPOCH FROM (agent_enriched_at - ingest_timestamp))
        ELSE NULL 
    END as enrichment_duration_seconds,
    CASE 
        WHEN response_received_at IS NOT NULL AND agent_enriched_at IS NOT NULL 
        THEN EXTRACT(EPOCH FROM (response_received_at - agent_enriched_at))
        ELSE NULL 
    END as llm_duration_seconds,
    CASE 
        WHEN structured_at IS NOT NULL AND response_received_at IS NOT NULL 
        THEN EXTRACT(EPOCH FROM (structured_at - response_received_at))
        ELSE NULL 
    END as structuring_duration_seconds,
    CASE 
        WHEN formatted_at IS NOT NULL AND structured_at IS NOT NULL 
        THEN EXTRACT(EPOCH FROM (formatted_at - structured_at))
        ELSE NULL 
    END as formatting_duration_seconds,
    CASE 
        WHEN alert_sent_at IS NOT NULL AND formatted_at IS NOT NULL 
        THEN EXTRACT(EPOCH FROM (alert_sent_at - formatted_at))
        ELSE NULL 
    END as sending_duration_seconds,
    -- Total end-to-end time
    CASE 
        WHEN alert_sent_at IS NOT NULL AND ingest_timestamp IS NOT NULL 
        THEN EXTRACT(EPOCH FROM (alert_sent_at - ingest_timestamp))
        ELSE NULL 
    END as total_duration_seconds,
    -- Parser performance indicators
    CASE 
        WHEN parser_success = FALSE THEN 'Parser Failed'
        WHEN parser_duration_ms > 5000 THEN 'Slow Parse'
        WHEN parser_duration_ms < 100 THEN 'Fast Parse'
        ELSE 'Normal Parse'
    END as parser_performance
FROM alerts
WHERE state IN ('new', 'agent_enriched', 'summarized', 'structured', 'formatted', 'sent')
ORDER BY ingest_timestamp DESC;

-- Parser health function with enhanced metrics
CREATE OR REPLACE FUNCTION get_parser_health(
    time_window INTERVAL DEFAULT '1 hour'
) RETURNS TABLE (
    prompt_type VARCHAR,
    total_attempts BIGINT,
    success_rate DECIMAL,
    avg_duration_ms DECIMAL,
    current_failures BIGINT,
    health_status TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        pm.prompt_type,
        COUNT(*) as total_attempts,
        ROUND(
            (SUM(CASE WHEN pm.success THEN 1 ELSE 0 END)::decimal / COUNT(*)) * 100, 
            2
        ) as success_rate,
        ROUND(AVG(pm.parse_time_ms), 2) as avg_duration_ms,
        COUNT(CASE WHEN NOT pm.success THEN 1 END) as current_failures,
        CASE 
            WHEN ROUND((SUM(CASE WHEN pm.success THEN 1 ELSE 0 END)::decimal / COUNT(*)) * 100, 2) >= 95 
                 AND AVG(pm.parse_time_ms) < 1000 THEN 'HEALTHY'
            WHEN ROUND((SUM(CASE WHEN pm.success THEN 1 ELSE 0 END)::decimal / COUNT(*)) * 100, 2) >= 80 
                 AND AVG(pm.parse_time_ms) < 3000 THEN 'WARNING'
            ELSE 'CRITICAL'
        END as health_status
    FROM parser_metrics pm
    WHERE pm.created_at > NOW() - time_window
    GROUP BY pm.prompt_type
    ORDER BY success_rate DESC;
END;
$$ LANGUAGE plpgsql;

-- ═══════════════════════════════════════════════════════════════════════════════
-- MEDIUM FIX #3: Create Proper Indexes for Performance
-- ═══════════════════════════════════════════════════════════════════════════════

-- Indexes for alert processing pipeline
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_state_agent_enriched 
ON alerts (state) WHERE state = 'agent_enriched';

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_state_summarized 
ON alerts (state) WHERE state = 'summarized';

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_state_structured 
ON alerts (state) WHERE state = 'structured';

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_state_formatted 
ON alerts (state) WHERE state = 'formatted';

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_agent_enriched_at 
ON alerts (agent_enriched_at) WHERE agent_enriched_at IS NOT NULL;

-- Indexes for prompt tracking columns
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_prompt_type 
ON alerts (prompt_type) WHERE prompt_type IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_parser_success 
ON alerts (parser_success, prompt_type) WHERE parser_success IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_parser_duration 
ON alerts (parser_duration_ms) WHERE parser_duration_ms IS NOT NULL;

-- Indexes for parser metrics table
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_parser_metrics_prompt_type 
ON parser_metrics (prompt_type, created_at);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_parser_metrics_success 
ON parser_metrics (success, prompt_type, created_at);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_parser_metrics_created_at 
ON parser_metrics (created_at);

-- ═══════════════════════════════════════════════════════════════════════════════
-- MEDIUM FIX #4: Grant Proper Permissions
-- ═══════════════════════════════════════════════════════════════════════════════

DO $$
BEGIN
    -- Grant permissions for wazuh services
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'wazuh') THEN
        -- Table permissions
        GRANT SELECT, INSERT, UPDATE ON alerts TO wazuh;
        GRANT SELECT, INSERT ON parser_metrics TO wazuh;
        GRANT USAGE ON SEQUENCE parser_metrics_id_seq TO wazuh;
        
        -- View permissions
        GRANT SELECT ON parser_performance TO wazuh;
        GRANT SELECT ON prompt_usage_stats TO wazuh;
        GRANT SELECT ON alert_processing_status TO wazuh;
        
        -- Function permissions
        GRANT EXECUTE ON FUNCTION get_parser_health(INTERVAL) TO wazuh;
    END IF;
    
    -- Grant permissions for stanley user (commonly used)
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stanley') THEN
        -- Table permissions
        GRANT SELECT, INSERT, UPDATE ON alerts TO stanley;
        GRANT SELECT, INSERT ON parser_metrics TO stanley;
        GRANT USAGE ON SEQUENCE parser_metrics_id_seq TO stanley;
        
        -- View permissions
        GRANT SELECT ON parser_performance TO stanley;
        GRANT SELECT ON prompt_usage_stats TO stanley;
        GRANT SELECT ON alert_processing_status TO stanley;
        
        -- Function permissions
        GRANT EXECUTE ON FUNCTION get_parser_health(INTERVAL) TO stanley;
    END IF;
EXCEPTION
    WHEN insufficient_privilege THEN
        -- User running migration might not have permission to grant privileges
        -- This is ok, privileges can be granted manually later
        NULL;
END $$;

COMMIT;

-- ═══════════════════════════════════════════════════════════════════════════════
-- POST-MIGRATION VERIFICATION QUERIES
-- ═══════════════════════════════════════════════════════════════════════════════

/*
-- Verify alert_state enum has all required values
SELECT enumlabel 
FROM pg_enum 
WHERE enumtypid = 'alert_state'::regtype 
ORDER BY enumsortorder;

-- Expected: new, agent_enriched, summarized, structured, formatted, sent, failed, archived

-- Verify all required columns exist
SELECT column_name, data_type, is_nullable 
FROM information_schema.columns 
WHERE table_name = 'alerts' 
AND column_name IN (
    'agent_enriched_at', 'structured_at', 'formatted_at',
    'prompt_type', 'parser_used', 'parser_success', 'parser_duration_ms'
);

-- Verify parser_metrics table schema
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'parser_metrics' 
ORDER BY ordinal_position;

-- Verify triggers exist
SELECT trigger_name, event_manipulation, action_timing 
FROM information_schema.triggers 
WHERE event_object_table = 'alerts';

-- Test notification channels (run manually in psql)
-- NOTIFY new_alert, '123';
-- NOTIFY agent_enriched, '123';
-- NOTIFY new_response, '123';
-- NOTIFY alert_structured, '123';
-- NOTIFY alert_formatted, '123';

-- Test views work
SELECT * FROM parser_performance LIMIT 5;
SELECT * FROM prompt_usage_stats LIMIT 5;
SELECT * FROM alert_processing_status LIMIT 5;

-- Test health function
SELECT * FROM get_parser_health('24 hours'::INTERVAL);
*/