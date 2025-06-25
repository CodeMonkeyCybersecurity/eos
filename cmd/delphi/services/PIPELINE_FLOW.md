# Delphi Modular Email Pipeline Flow

## Overview

The Delphi email processing has been refactored from a monolithic `delphi-emailer` service into three modular services that handle different aspects of email processing:

1. **email-structurer** - Parses LLM responses into structured sections
2. **email-formatter** - Formats structured data into HTML/plain text emails  
3. **email-sender** - Delivers formatted emails via SMTP

## PostgreSQL Notification Chain

The services communicate through PostgreSQL's LISTEN/NOTIFY mechanism:

```
┌─────────────────┐    NOTIFY        ┌─────────────────┐    NOTIFY        ┌─────────────────┐    NOTIFY        ┌─────────────────┐
│   LLM Worker    │ ──────────────→  │ Email Structurer│ ──────────────→  │ Email Formatter │ ──────────────→  │  Email Sender   │
│                 │  new_response    │                 │ alert_structured │                 │ alert_formatted │                 │
└─────────────────┘                  └─────────────────┘                  └─────────────────┘                  └─────────────────┘
       ↓                                      ↓                                      ↓                                      ↓
   state =                               state =                               state =                               state =
 'summarized'                         'structured'                         'formatted'                             'sent'
```

## Notification Channels

| Channel | Sender | Listener | Payload | Purpose |
|---------|--------|----------|---------|---------|
| `new_response` | LLM Worker / prompt-ab-tester | email-structurer | `alert_id` | Triggers structuring of summarized alerts |
| `alert_structured` | email-structurer | email-formatter | `alert_id` | Triggers formatting of structured alerts |
| `alert_formatted` | email-formatter | email-sender | `alert_id` | Triggers sending of formatted emails |

## Database State Flow

### Alert States
The `alert_state` enum has been extended to support the modular pipeline:

1. `new` - Initial state when alert is created
2. `agent_enriched` - After agent enrichment
3. `summarized` - After LLM processing  
4. **`structured`** - After email structuring *(NEW)*
5. **`formatted`** - After email formatting *(NEW)*
6. **`sent`** - After email delivery *(NEW)*

### Database Schema Changes

**New Columns Added to `alerts` table:**
```sql
-- Structured data from email-structurer
structured_data JSONB              -- Parsed sections, agent info, metadata
structured_at TIMESTAMP WITH TIME ZONE

-- Formatted email data from email-formatter  
formatted_data JSONB              -- HTML/plain text bodies, subject
formatted_at TIMESTAMP WITH TIME ZONE
```

**Example `structured_data` format:**
```json
{
  "subject": "[Delphi Notify] Agent001 (Ubuntu 20.04) Level 7",
  "sections": {
    "Summary": "Failed login attempt detected...",
    "What happened": "Multiple failed SSH login attempts...",
    "What to do": "Check for suspicious activity..."
  },
  "agent_info": {
    "name": "Agent001", 
    "ip": "192.168.1.100",
    "os": "Ubuntu 20.04.3 LTS (x86_64)"
  },
  "metadata": {
    "alert_id": 12345,
    "alert_hash": "abc123",
    "rule_level": 7,
    "timestamp": "2025-01-20T10:30:00Z"
  }
}
```

**Example `formatted_data` format:**
```json
{
  "subject": "[Delphi Notify] Agent001 (Ubuntu 20.04) Level 7",
  "html_body": "<!DOCTYPE html><html>...",
  "plain_body": "Subject: [Delphi Notify]...",
  "template_used": "file_based",
  "formatting_metadata": {
    "template_path": "/opt/stackstorm/packs/delphi/email.html",
    "formatted_at": "2025-01-20T10:30:15Z"
  }
}
```

## Service Configuration

### email-structurer Configuration

**Environment Variables:**
```bash
# Parser type selection
DELPHI_PARSER_TYPE=standard          # standard|threat|bullet|custom
DELPHI_CUSTOM_SECTIONS=Summary,Actions,Next Steps  # For custom parser

# Database connection
PG_DSN=postgresql://user:pass@host:5432/delphi
```

**Supported Parser Types:**
- `standard` - Standard Delphi 7-section format
- `threat` - Threat analysis focused sections  
- `bullet` - Simple bullet-point format
- `custom` - User-defined sections via DELPHI_CUSTOM_SECTIONS

### email-formatter Configuration  

**Environment Variables:**
```bash
# Template configuration
DELPHI_EMAIL_TEMPLATE_TYPE=file      # file|modern|custom
DELPHI_EMAIL_TEMPLATE_PATH=/opt/stackstorm/packs/delphi/email.html

# Timezone for timestamps
DELPHI_TIMEZONE=Australia/Perth

# Support contact
SUPPORT_EMAIL=support@cybermonkey.net.au
```

## Processing Pipeline Monitoring

### View for Pipeline Status
A new view `alert_processing_status` provides visibility into the pipeline:

```sql
SELECT 
    alert_hash,
    processing_stage,
    structuring_duration_seconds,
    formatting_duration_seconds
FROM alert_processing_status 
WHERE created_at > NOW() - INTERVAL '1 hour';
```

### Metrics Collection
Each service logs structured metrics for monitoring:

- **Processing duration** for each stage
- **Success/failure rates** per service
- **Backlog size** (alerts waiting in each state)
- **Template usage** and performance

### Health Checks
Services provide health information via:
- **Heartbeat files** (similar to existing workers)
- **PostgreSQL connection status**
- **Processing queue depth**
- **Last successful operation timestamp**

## Error Handling & Recovery

### Service Failure Recovery
- Each service processes backlog on startup
- Failed operations remain in previous state for retry
- Services can be restarted independently
- Dead letter queue for persistently failing alerts

### Data Consistency
- All state transitions are atomic
- JSONB data includes metadata for debugging
- Timestamps track progression through pipeline
- Failed operations log detailed error context

## Backward Compatibility

### Migration Strategy
1. **Phase 1**: Deploy new services alongside existing `delphi-emailer`
2. **Phase 2**: Run both systems in parallel with feature flags
3. **Phase 3**: Migrate alerts to new pipeline states
4. **Phase 4**: Deprecate and remove `delphi-emailer`

### Rollback Plan
- Old `delphi-emailer` can still process `summarized` alerts
- New columns are nullable and don't break existing queries
- Services can be disabled individually if issues arise

## Performance Considerations

### Database Impact
- New indexes on state and timestamp columns
- JSONB GIN indexes for efficient querying
- Partitioning recommendations for high-volume deployments

### Scalability
- Services can be horizontally scaled
- PostgreSQL NOTIFY handles fan-out efficiently
- Each service maintains independent processing rates

### Resource Usage
- Lower memory footprint per service
- Better CPU utilization through specialization
- Reduced database connection pressure

---

*This document describes the modular email processing pipeline that replaces the monolithic delphi-emailer service.*