-- Migration: Add prompt tracking to alerts table
-- Description: Adds columns to track which prompt was used and parser performance
-- Date: 2025-01-XX
-- Author: DevSecOps Pipeline - Prompt-Aware Parsing

BEGIN;

-- Add prompt tracking columns to alerts table
ALTER TABLE alerts 
ADD COLUMN IF NOT EXISTS prompt_type VARCHAR(100);

ALTER TABLE alerts 
ADD COLUMN IF NOT EXISTS prompt_template TEXT;

ALTER TABLE alerts 
ADD COLUMN IF NOT EXISTS parser_used VARCHAR(100);

ALTER TABLE alerts 
ADD COLUMN IF NOT EXISTS parser_success BOOLEAN DEFAULT TRUE;

ALTER TABLE alerts 
ADD COLUMN IF NOT EXISTS parser_error TEXT;

ALTER TABLE alerts 
ADD COLUMN IF NOT EXISTS parser_duration_ms INTEGER;

-- Create indexes for efficient querying
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_prompt_type 
ON alerts (prompt_type) WHERE prompt_type IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_parser_success 
ON alerts (parser_success, prompt_type) WHERE parser_success IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_parser_duration 
ON alerts (parser_duration_ms) WHERE parser_duration_ms IS NOT NULL;

-- Create a table for parser performance metrics
CREATE TABLE IF NOT EXISTS parser_metrics (
    id SERIAL PRIMARY KEY,
    alert_id INTEGER REFERENCES alerts(id),
    prompt_type VARCHAR(100) NOT NULL,
    parser_used VARCHAR(100) NOT NULL,
    success BOOLEAN NOT NULL,
    parse_time_ms INTEGER NOT NULL,
    sections_extracted INTEGER DEFAULT 0,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Index for parser metrics
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_parser_metrics_prompt_type 
ON parser_metrics (prompt_type, created_at);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_parser_metrics_success 
ON parser_metrics (success, prompt_type, created_at);

-- Create a view for parser performance analysis
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
    AVG(parse_time_ms) as avg_parse_time_ms,
    MAX(parse_time_ms) as max_parse_time_ms,
    AVG(sections_extracted) as avg_sections_extracted,
    COUNT(CASE WHEN NOT success THEN 1 END) as failure_count,
    MAX(created_at) as last_attempt
FROM parser_metrics
WHERE created_at > NOW() - INTERVAL '7 days'
GROUP BY prompt_type, parser_used
ORDER BY prompt_type, success_rate_percent DESC;

-- Create a view for prompt distribution analysis
CREATE OR REPLACE VIEW prompt_usage_stats AS
SELECT 
    prompt_type,
    COUNT(*) as total_alerts,
    COUNT(CASE WHEN state >= 'structured' THEN 1 END) as successfully_structured,
    COUNT(CASE WHEN parser_success = FALSE THEN 1 END) as parser_failures,
    ROUND(
        (COUNT(CASE WHEN state >= 'structured' THEN 1 END)::decimal / COUNT(*)) * 100, 
        2
    ) as processing_success_rate,
    AVG(parser_duration_ms) as avg_parser_duration_ms,
    MIN(created_at) as first_used,
    MAX(created_at) as last_used
FROM alerts
WHERE prompt_type IS NOT NULL 
  AND created_at > NOW() - INTERVAL '7 days'
GROUP BY prompt_type
ORDER BY total_alerts DESC;

-- Update the existing alert_processing_status view to include prompt info
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
    created_at,
    response_received_at,
    structured_at,
    formatted_at,
    CASE 
        WHEN state = 'sent' THEN 'Complete'
        WHEN state = 'formatted' THEN 'Ready for Sending'
        WHEN state = 'structured' THEN 'Ready for Formatting'
        WHEN state = 'summarized' THEN 'Ready for Structuring'
        ELSE 'Processing'
    END as processing_stage,
    -- Calculate processing durations
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
    -- Parser performance indicators
    CASE 
        WHEN parser_success = FALSE THEN 'Parser Failed'
        WHEN parser_duration_ms > 5000 THEN 'Slow Parse'
        WHEN parser_duration_ms < 100 THEN 'Fast Parse'
        ELSE 'Normal Parse'
    END as parser_performance
FROM alerts
WHERE state IN ('summarized', 'structured', 'formatted', 'sent')
ORDER BY created_at DESC;

-- Create a function to get parser metrics for monitoring
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

-- Grant permissions for the delphi services
DO $$
BEGIN
    -- Grant INSERT/UPDATE on new tables for metric collection
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'delphi') THEN
        GRANT SELECT, INSERT ON parser_metrics TO delphi;
        GRANT USAGE ON SEQUENCE parser_metrics_id_seq TO delphi;
        GRANT SELECT ON parser_performance TO delphi;
        GRANT SELECT ON prompt_usage_stats TO delphi;
        GRANT EXECUTE ON FUNCTION get_parser_health(INTERVAL) TO delphi;
    END IF;
    
    -- Grant similar permissions to stanley user if it exists
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stanley') THEN
        GRANT SELECT, INSERT ON parser_metrics TO stanley;
        GRANT USAGE ON SEQUENCE parser_metrics_id_seq TO stanley;
        GRANT SELECT ON parser_performance TO stanley;
        GRANT SELECT ON prompt_usage_stats TO stanley;
        GRANT EXECUTE ON FUNCTION get_parser_health(INTERVAL) TO stanley;
    END IF;
EXCEPTION
    WHEN insufficient_privilege THEN
        -- User running migration might not have permission to grant privileges
        NULL;
END $$;

COMMIT;

-- Post-migration verification queries
-- These should be run manually to verify the migration succeeded

/*
-- Verify new columns exist
SELECT column_name, data_type, is_nullable 
FROM information_schema.columns 
WHERE table_name = 'alerts' 
AND column_name IN ('prompt_type', 'prompt_template', 'parser_used', 'parser_success', 'parser_error', 'parser_duration_ms');

-- Verify parser_metrics table exists
SELECT table_name, column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'parser_metrics' 
ORDER BY ordinal_position;

-- Verify indexes were created
SELECT indexname, tablename 
FROM pg_indexes 
WHERE tablename IN ('alerts', 'parser_metrics') 
AND (indexname LIKE '%prompt%' OR indexname LIKE '%parser%');

-- Test the views
SELECT * FROM parser_performance LIMIT 5;
SELECT * FROM prompt_usage_stats LIMIT 5;

-- Test the health function
SELECT * FROM get_parser_health('24 hours'::INTERVAL);

-- Test updating an alert with prompt information
-- UPDATE alerts SET prompt_type = 'delphi_notify_short', parser_used = 'DelphiNotifyShortParser' WHERE id = 1;
*/