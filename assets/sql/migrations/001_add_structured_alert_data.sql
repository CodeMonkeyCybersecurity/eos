-- Migration: Add structured data columns to alerts table
-- Description: Adds columns to support the modular email processing pipeline
-- Date: 2025-01-XX
-- Author: DevSecOps Pipeline

BEGIN;

-- Add 'structured' state to alert_state enum if it doesn't exist
DO $$ 
BEGIN
    -- Check if the enum value already exists
    IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'structured' AND enumtypid = 'alert_state'::regtype) THEN
        ALTER TYPE alert_state ADD VALUE 'structured' AFTER 'summarized';
    END IF;
EXCEPTION
    WHEN duplicate_object THEN
        -- Value already exists, continue
        NULL;
END $$;

-- Add structured_data column to store parsed alert sections
ALTER TABLE alerts 
ADD COLUMN IF NOT EXISTS structured_data JSONB;

-- Add timestamp for when structuring was completed
ALTER TABLE alerts 
ADD COLUMN IF NOT EXISTS structured_at TIMESTAMP WITH TIME ZONE;

-- Add formatted email data columns for the formatter service
ALTER TABLE alerts 
ADD COLUMN IF NOT EXISTS formatted_data JSONB;

-- Add timestamp for when formatting was completed
ALTER TABLE alerts 
ADD COLUMN IF NOT EXISTS formatted_at TIMESTAMP WITH TIME ZONE;

-- Add 'formatted' state to alert_state enum for the next stage
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'formatted' AND enumtypid = 'alert_state'::regtype) THEN
        ALTER TYPE alert_state ADD VALUE 'formatted' AFTER 'structured';
    END IF;
EXCEPTION
    WHEN duplicate_object THEN
        NULL;
END $$;

-- Add 'sent' state for final email delivery stage
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_enum WHERE enumlabel = 'sent' AND enumtypid = 'alert_state'::regtype) THEN
        ALTER TYPE alert_state ADD VALUE 'sent' AFTER 'formatted';
    END IF;
EXCEPTION
    WHEN duplicate_object THEN
        NULL;
END $$;

-- Create indexes for efficient querying
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_state_structured 
ON alerts (state) WHERE state = 'structured';

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_state_formatted 
ON alerts (state) WHERE state = 'formatted';

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_structured_at 
ON alerts (structured_at) WHERE structured_at IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_formatted_at 
ON alerts (formatted_at) WHERE formatted_at IS NOT NULL;

-- Add GIN index for JSONB structured_data queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_structured_data_gin 
ON alerts USING GIN (structured_data) WHERE structured_data IS NOT NULL;

-- Add GIN index for JSONB formatted_data queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_formatted_data_gin 
ON alerts USING GIN (formatted_data) WHERE formatted_data IS NOT NULL;

-- Create a view for the modular email processing pipeline status
CREATE OR REPLACE VIEW alert_processing_status AS
SELECT 
    id,
    alert_hash,
    agent_id,
    rule_level,
    state,
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
    END as formatting_duration_seconds
FROM alerts
WHERE state IN ('summarized', 'structured', 'formatted', 'sent')
ORDER BY created_at DESC;

-- Grant permissions for the wazuh services
-- Note: Adjust role names based on your PostgreSQL setup
DO $$
BEGIN
    -- Grant SELECT, UPDATE on alerts table for structured data operations
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'wazuh') THEN
        GRANT SELECT, UPDATE ON alerts TO wazuh;
        GRANT SELECT ON alert_processing_status TO wazuh;
    END IF;
    
    -- Grant similar permissions to stanley user if it exists
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'stanley') THEN
        GRANT SELECT, UPDATE ON alerts TO stanley;
        GRANT SELECT ON alert_processing_status TO stanley;
    END IF;
EXCEPTION
    WHEN insufficient_privilege THEN
        -- User running migration might not have permission to grant privileges
        -- This is ok, privileges can be granted manually later
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
AND column_name IN ('structured_data', 'structured_at', 'formatted_data', 'formatted_at');

-- Verify new enum values exist
SELECT enumlabel 
FROM pg_enum 
WHERE enumtypid = 'alert_state'::regtype 
ORDER BY enumsortorder;

-- Verify indexes were created
SELECT indexname, tablename 
FROM pg_indexes 
WHERE tablename = 'alerts' 
AND indexname LIKE '%structured%' OR indexname LIKE '%formatted%';

-- Check the processing status view
SELECT * FROM alert_processing_status LIMIT 5;

-- Test the notification flow (run manually in psql)
-- NOTIFY alert_structured, '123';
-- NOTIFY alert_formatted, '123';
*/