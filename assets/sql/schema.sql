-- /opt/stackstorm/packs/delphi/sql/schema_v2.sql
-- This schema supports intelligent prompt selection and parsing
-- Last Updated: Database migration completed with enhanced monitoring views

-- ═══════════════════════════════════════════════════════════════
-- ENUM TYPES - Consistent naming for state management
-- ═══════════════════════════════════════════════════════════════

-- Alert processing states
CREATE TYPE alert_state AS ENUM (
    'new',           -- Received from Wazuh
    'enriched',      -- Agent metadata added
    'analyzed',      -- LLM processing complete
    'structured',    -- Parsed into sections
    'formatted',     -- Email generated
    'sent',          -- Delivered successfully
    'failed',        -- Terminal failure
    'archived'       -- Soft delete
);

-- Parser types for intelligent routing
CREATE TYPE parser_type AS ENUM (
    'security_analysis',
    'executive_summary',
    'investigation_guide',
    'delphi_notify_short',
    'hybrid',
    'custom'
);

-- ═══════════════════════════════════════════════════════════════
-- AGENTS TABLE - Comprehensive endpoint tracking
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS agents (
    -- Core identification
    id                  TEXT PRIMARY KEY,
    name                TEXT NOT NULL,
    ip                  TEXT,
    os                  TEXT,
    
    -- Temporal tracking
    registered          TIMESTAMPTZ NOT NULL,
    last_seen           TIMESTAMPTZ DEFAULT NOW(),
    disconnection_time  TIMESTAMPTZ,
    
    -- Wazuh integration
    agent_version       TEXT,
    register_ip         TEXT,
    node_name           TEXT,
    config_sum          TEXT,
    merged_sum          TEXT,
    group_config_status TEXT,
    status_text         TEXT,
    status_code_api     INTEGER,
    groups              JSONB DEFAULT '[]'::jsonb,
    manager_name        TEXT,
    
    -- API tracking
    api_response        JSONB,
    api_fetch_timestamp TIMESTAMPTZ,
    
    -- Indexes for performance
    CONSTRAINT agents_name_unique UNIQUE (name)
);

CREATE INDEX idx_agents_status ON agents(status_text);
CREATE INDEX idx_agents_last_seen ON agents(last_seen DESC);
CREATE INDEX idx_agents_groups ON agents USING GIN (groups);

-- ═══════════════════════════════════════════════════════════════
-- ALERTS TABLE - Complete pipeline tracking
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS alerts (
    -- Identity and deduplication
    id                   BIGSERIAL PRIMARY KEY,
    alert_hash           TEXT UNIQUE NOT NULL,
    
    -- Source information
    agent_id             TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    rule_id              INTEGER NOT NULL,
    rule_level           INTEGER NOT NULL,
    rule_desc            TEXT NOT NULL,
    raw                  JSONB NOT NULL,
    
    -- Pipeline state
    state                alert_state DEFAULT 'new' NOT NULL,
    ingest_timestamp     TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    
    -- Enrichment phase
    agent_data           JSONB,
    enriched_at          TIMESTAMPTZ,
    
    -- LLM analysis phase
    prompt_type          VARCHAR(50),
    prompt_template      TEXT,
    prompt_text          TEXT,
    prompt_sent_at       TIMESTAMPTZ,
    response_text        TEXT,
    response_received_at TIMESTAMPTZ,
    prompt_tokens        INTEGER,
    completion_tokens    INTEGER,
    total_tokens         INTEGER,
    
    -- Parsing phase
    parser_used          VARCHAR(50),
    parser_success       BOOLEAN,
    parser_error         TEXT,
    parser_duration_ms   INTEGER,
    structured_data      JSONB,
    structured_at        TIMESTAMPTZ,
    
    -- Formatting phase
    formatted_data       JSONB,
    formatted_at         TIMESTAMPTZ,
    
    -- Delivery phase
    email_recipients     JSONB,
    email_error          TEXT,
    email_retry_count    INTEGER DEFAULT 0,
    alert_sent_at        TIMESTAMPTZ,
    
    -- Archival
    archived_at          TIMESTAMPTZ,
    
    -- Constraints
    CONSTRAINT valid_rule_level CHECK (rule_level BETWEEN 0 AND 15),
    CONSTRAINT valid_token_counts CHECK (
        (prompt_tokens IS NULL AND completion_tokens IS NULL AND total_tokens IS NULL) OR
        (prompt_tokens >= 0 AND completion_tokens >= 0 AND total_tokens >= 0)
    )
);

-- Performance indexes
CREATE INDEX idx_alerts_state_timestamp ON alerts(state, ingest_timestamp DESC);
CREATE INDEX idx_alerts_agent_rule ON alerts(agent_id, rule_id);
CREATE INDEX idx_alerts_prompt_type ON alerts(prompt_type) WHERE prompt_type IS NOT NULL;
CREATE INDEX idx_alerts_parser_performance ON alerts(parser_used, parser_success) 
    WHERE parser_used IS NOT NULL;

-- ═══════════════════════════════════════════════════════════════
-- PARSER METRICS - Track parser performance
-- ═══════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS parser_metrics (
    id SERIAL PRIMARY KEY,
    alert_id INTEGER REFERENCES alerts(id),
    prompt_type VARCHAR(100) NOT NULL,
    parser_used VARCHAR(100) NOT NULL,
    success BOOLEAN NOT NULL,
    parse_time_ms INTEGER NOT NULL,
    sections_extracted INTEGER DEFAULT 0,
    error_message TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_parser_metrics_performance 
    ON parser_metrics(prompt_type, success, created_at DESC);

-- ═══════════════════════════════════════════════════════════════
-- NOTIFICATION FUNCTIONS - Pipeline orchestration
-- ═══════════════════════════════════════════════════════════════

-- State transition notifier for pipeline flow
CREATE OR REPLACE FUNCTION notify_state_change() 
RETURNS TRIGGER AS $$
DECLARE
    channel_name TEXT;
BEGIN
    -- Only notify on actual state changes
    IF OLD.state IS DISTINCT FROM NEW.state THEN
        -- Map states to notification channels
        channel_name := CASE NEW.state
            WHEN 'enriched' THEN 'alert_enriched'
            WHEN 'analyzed' THEN 'alert_analyzed'
            WHEN 'structured' THEN 'alert_structured'
            WHEN 'formatted' THEN 'alert_formatted'
            ELSE NULL
        END;
        
        IF channel_name IS NOT NULL THEN
            PERFORM pg_notify(channel_name, NEW.id::text);
            -- Log state transitions for debugging
            RAISE DEBUG 'Notified channel % for alert % (state: % -> %)', 
                channel_name, NEW.id, OLD.state, NEW.state;
        END IF;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- New alert notifier for pipeline initiation
CREATE OR REPLACE FUNCTION notify_new_alert()
RETURNS TRIGGER AS $$
BEGIN
    -- Notify when a new alert is inserted
    PERFORM pg_notify('new_alert', NEW.id::text);
    -- Log for debugging
    RAISE DEBUG 'New alert % created with initial state: %', NEW.id, NEW.state;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create triggers for notifications
CREATE TRIGGER trg_alert_state_change
    AFTER UPDATE OF state ON alerts
    FOR EACH ROW
    EXECUTE FUNCTION notify_state_change();

CREATE TRIGGER trg_alert_new
    AFTER INSERT ON alerts
    FOR EACH ROW
    EXECUTE FUNCTION notify_new_alert();

-- ═══════════════════════════════════════════════════════════════
-- ENHANCED MONITORING VIEWS - Operational visibility
-- ═══════════════════════════════════════════════════════════════

-- Pipeline health dashboard with status indicators
CREATE OR REPLACE VIEW pipeline_health AS
SELECT 
    state,
    COUNT(*) as count,
    MIN(ingest_timestamp) as oldest,
    MAX(ingest_timestamp) as newest,
    ROUND(AVG(EXTRACT(EPOCH FROM (NOW() - ingest_timestamp))), 2) as avg_age_seconds,
    ROUND(AVG(EXTRACT(EPOCH FROM (NOW() - ingest_timestamp))) / 60, 2) as avg_age_minutes,
    CASE 
        WHEN AVG(EXTRACT(EPOCH FROM (NOW() - ingest_timestamp))) > 3600 THEN 'ATTENTION NEEDED'
        WHEN AVG(EXTRACT(EPOCH FROM (NOW() - ingest_timestamp))) > 1800 THEN 'Monitor'
        ELSE 'Healthy'
    END as health_status
FROM alerts
WHERE archived_at IS NULL
GROUP BY state
ORDER BY 
    CASE state
        WHEN 'new' THEN 1
        WHEN 'enriched' THEN 2
        WHEN 'analyzed' THEN 3
        WHEN 'structured' THEN 4
        WHEN 'formatted' THEN 5
        WHEN 'sent' THEN 6
        WHEN 'failed' THEN 7
        WHEN 'archived' THEN 8
    END;

-- Pipeline bottleneck detection view
CREATE OR REPLACE VIEW pipeline_bottlenecks AS
SELECT 
    state,
    COUNT(*) FILTER (WHERE ingest_timestamp < NOW() - INTERVAL '1 hour') as stuck_over_1hr,
    COUNT(*) FILTER (WHERE ingest_timestamp < NOW() - INTERVAL '30 minutes') as stuck_over_30min,
    COUNT(*) FILTER (WHERE ingest_timestamp < NOW() - INTERVAL '10 minutes') as stuck_over_10min,
    COUNT(*) as total_in_state
FROM alerts
WHERE archived_at IS NULL 
    AND state NOT IN ('sent', 'archived', 'failed')
GROUP BY state
HAVING COUNT(*) > 0
ORDER BY stuck_over_1hr DESC;

-- Enhanced parser performance view with detailed metrics
CREATE OR REPLACE VIEW parser_performance AS
SELECT 
    COALESCE(prompt_type, 'not_set') as prompt_type,
    COALESCE(parser_used, 'not_set') as parser_used,
    COUNT(*) as total_attempts,
    SUM(CASE WHEN parser_success THEN 1 ELSE 0 END) as successes,
    SUM(CASE WHEN NOT parser_success OR parser_success IS NULL THEN 1 ELSE 0 END) as failures,
    ROUND(
        100.0 * SUM(CASE WHEN parser_success THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0), 
        2
    ) as success_rate,
    ROUND(AVG(parser_duration_ms), 2) as avg_duration_ms,
    MIN(parser_duration_ms) as min_duration_ms,
    MAX(parser_duration_ms) as max_duration_ms,
    MAX(structured_at) as last_used
FROM alerts
WHERE parser_used IS NOT NULL OR prompt_type IS NOT NULL
GROUP BY prompt_type, parser_used
ORDER BY total_attempts DESC;

-- Parser error analysis view
CREATE OR REPLACE VIEW parser_error_analysis AS
SELECT 
    prompt_type,
    parser_used,
    parser_error,
    COUNT(*) as error_count,
    MAX(structured_at) as most_recent_error,
    STRING_AGG(DISTINCT id::text, ', ' ORDER BY id::text) as affected_alert_ids
FROM alerts
WHERE parser_success = false 
    AND parser_error IS NOT NULL
    AND structured_at > NOW() - INTERVAL '24 hours'
GROUP BY prompt_type, parser_used, parser_error
ORDER BY error_count DESC
LIMIT 20;

-- Enhanced recent failures view with diagnostic information
CREATE OR REPLACE VIEW recent_failures AS
SELECT 
    id,
    state,
    agent_id,
    rule_level,
    parser_error,
    email_error,
    ingest_timestamp,
    ROUND(EXTRACT(EPOCH FROM (NOW() - ingest_timestamp))) as age_seconds,
    CASE 
        WHEN EXTRACT(EPOCH FROM (NOW() - ingest_timestamp)) < 300 THEN 'Just occurred'
        WHEN EXTRACT(EPOCH FROM (NOW() - ingest_timestamp)) < 3600 THEN 'Recent (< 1 hour)'
        WHEN EXTRACT(EPOCH FROM (NOW() - ingest_timestamp)) < 86400 THEN 'Today'
        ELSE 'Older'
    END as recency,
    COALESCE(
        parser_error,
        email_error,
        CASE 
            WHEN state = 'failed' THEN 'Alert in failed state - check logs'
            WHEN state = 'enriched' AND ingest_timestamp < NOW() - INTERVAL '1 hour' 
                THEN 'Stuck in enriched state - LLM worker may be down'
            WHEN state = 'analyzed' AND ingest_timestamp < NOW() - INTERVAL '30 minutes'
                THEN 'Stuck in analyzed state - Parser may be failing'
            ELSE 'Unknown failure reason'
        END
    ) as failure_reason
FROM alerts
WHERE (
    state = 'failed'
    OR (parser_success = FALSE AND parser_error IS NOT NULL)
    OR (email_error IS NOT NULL AND email_retry_count >= 3)
    OR (state = 'enriched' AND ingest_timestamp < NOW() - INTERVAL '2 hours')
    OR (state = 'analyzed' AND ingest_timestamp < NOW() - INTERVAL '1 hour')
)
AND archived_at IS NULL
ORDER BY ingest_timestamp DESC
LIMIT 50;

-- Failure summary view for pattern detection
CREATE OR REPLACE VIEW failure_summary AS
SELECT 
    CASE 
        WHEN state = 'failed' THEN 'Explicit failure'
        WHEN parser_success = FALSE THEN 'Parser failure'
        WHEN email_error IS NOT NULL THEN 'Email failure'
        WHEN state = 'enriched' AND ingest_timestamp < NOW() - INTERVAL '2 hours' THEN 'Stuck at enrichment'
        WHEN state = 'analyzed' AND ingest_timestamp < NOW() - INTERVAL '1 hour' THEN 'Stuck at parsing'
        ELSE 'Other'
    END as failure_type,
    COUNT(*) as count,
    MIN(ingest_timestamp) as oldest_failure,
    MAX(ingest_timestamp) as newest_failure
FROM alerts
WHERE (
    state = 'failed'
    OR parser_success = FALSE
    OR (email_error IS NOT NULL AND email_retry_count >= 3)
    OR (state IN ('enriched', 'analyzed') AND ingest_timestamp < NOW() - INTERVAL '1 hour')
)
AND archived_at IS NULL
GROUP BY failure_type
ORDER BY count DESC;

-- ═══════════════════════════════════════════════════════════════
-- HELPER FUNCTIONS - Operational utilities
-- ═══════════════════════════════════════════════════════════════

-- Function to archive old processed alerts
CREATE OR REPLACE FUNCTION archive_old_alerts(days_to_keep INTEGER DEFAULT 30) 
RETURNS INTEGER AS $$
DECLARE
    archived_count INTEGER;
BEGIN
    UPDATE alerts 
    SET archived_at = NOW()
    WHERE state = 'sent' 
        AND alert_sent_at < NOW() - INTERVAL '1 day' * days_to_keep
        AND archived_at IS NULL;
    
    GET DIAGNOSTICS archived_count = ROW_COUNT;
    RETURN archived_count;
END;
$$ LANGUAGE plpgsql;

-- Function to get pipeline statistics
CREATE OR REPLACE FUNCTION get_pipeline_stats()
RETURNS TABLE (
    metric_name TEXT,
    metric_value NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT 'total_alerts_24h'::TEXT, COUNT(*)::NUMERIC
    FROM alerts WHERE ingest_timestamp > NOW() - INTERVAL '24 hours'
    UNION ALL
    SELECT 'successful_deliveries_24h'::TEXT, COUNT(*)::NUMERIC
    FROM alerts WHERE state = 'sent' AND alert_sent_at > NOW() - INTERVAL '24 hours'
    UNION ALL
    SELECT 'average_processing_time_seconds'::TEXT, 
        ROUND(AVG(EXTRACT(EPOCH FROM (alert_sent_at - ingest_timestamp))))::NUMERIC
    FROM alerts WHERE state = 'sent' AND alert_sent_at > NOW() - INTERVAL '24 hours'
    UNION ALL
    SELECT 'current_backlog'::TEXT, COUNT(*)::NUMERIC
    FROM alerts WHERE state NOT IN ('sent', 'failed', 'archived') AND archived_at IS NULL;
END;
$$ LANGUAGE plpgsql;

-- ═══════════════════════════════════════════════════════════════
-- DOCUMENTATION
-- ═══════════════════════════════════════════════════════════════

COMMENT ON TABLE agents IS 'Wazuh agent metadata and status tracking';
COMMENT ON TABLE alerts IS 'Security alert pipeline with full audit trail';
COMMENT ON TABLE parser_metrics IS 'Parser performance tracking for optimization';
COMMENT ON VIEW pipeline_health IS 'Real-time pipeline status with health indicators';
COMMENT ON VIEW pipeline_bottlenecks IS 'Identifies where alerts are getting stuck in the pipeline';
COMMENT ON VIEW parser_performance IS 'Comprehensive parser effectiveness metrics';
COMMENT ON VIEW parser_error_analysis IS 'Groups parser errors for pattern detection';
COMMENT ON VIEW recent_failures IS 'Recent failures with automatic diagnostic suggestions';
COMMENT ON VIEW failure_summary IS 'High-level failure pattern analysis';
COMMENT ON FUNCTION archive_old_alerts IS 'Archives processed alerts older than specified days';
COMMENT ON FUNCTION get_pipeline_stats IS 'Returns key pipeline metrics for monitoring';