# Delphi Pipeline: Target Architecture

## The Vision: A Smart, Self-Adapting Alert Pipeline

Think of your pipeline like a sophisticated translation service. Raw security alerts come in speaking a technical language, and your pipeline translates them into clear, actionable emails that different audiences can understand. The key innovation you're working towards is having multiple "translators" (parsers) that specialize in different communication styles.

## Complete Pipeline Architecture

### Phase 1: Alert Ingestion & Initial Processing
```
Wazuh Alert → Webhook Listener → Database (state: 'new')
                                     ↓
                            Agent Enricher adds context
                                     ↓
                            Database (state: 'agent_enriched')
```

At this stage, your raw alert has been received and enriched with information about the agent that generated it. This is like receiving a letter in a foreign language and noting who sent it and where it came from.

### Phase 2: Intelligent Prompt Selection & LLM Processing
```
Alert Ready for Analysis → Prompt Selector chooses approach
                                     ↓
                          Random selection from:
                          - Security Analysis (detailed technical)
                          - Executive Summary (business-focused)
                          - Investigation Guide (step-by-step)
                          - Concise Notification (your current format)
                                     ↓
                          LLM processes with selected prompt
                                     ↓
                 Database (state: 'responded', prompt_type set)
```

This is where the magic happens. Instead of using the same prompt for every alert, your system should intelligently select different prompts based on factors like:
- Alert severity
- Time of day (executives might prefer summaries during business hours)
- Alert type (some alerts benefit from investigation guides)
- Historical effectiveness (which formats get the best response?)

### Phase 3: Smart Parsing with Fallback Protection
```
LLM Response → Parser Registry checks prompt_type
                        ↓
              Selects appropriate parser:
              - SecurityAnalysisParser
              - ExecutiveSummaryParser
              - InvestigationGuideParser
              - DelphiNotifyShortParser
                        ↓
              Attempts parsing with validation
                        ↓
    Success?  ──No──→ Circuit breaker counts failure
       ↓                        ↓
      Yes              After 5 failures: Open circuit
       ↓                        ↓
Store structured data    Use fallback parser
       ↓                        ↓
Database (state: 'structured', parser_used recorded)
```

The parsing phase is like having specialized editors who know how to format different types of documents. Each parser understands the structure its corresponding prompt produces.

### Phase 4: Email Generation & Delivery
```
Structured Data → Email Formatter applies template
                            ↓
                   Creates HTML and plain text
                            ↓
              Database (state: 'formatted')
                            ↓
                     Email Sender
                            ↓
              Database (state: 'sent')
```

## Database Schema: The Complete Picture

Your database should track the entire journey of each alert. Here's what each field means and why it matters:

```sql
CREATE TABLE alerts (
    -- Identity & Deduplication
    id BIGINT PRIMARY KEY,
    alert_hash TEXT UNIQUE,      -- Prevents duplicate processing
    
    -- Source Information
    agent_id TEXT,               -- Which system generated this?
    rule_id INTEGER,             -- What rule triggered?
    rule_level INTEGER,          -- How severe? (1-15 scale)
    rule_desc TEXT,              -- Human-readable rule description
    raw JSONB,                   -- Original Wazuh data (for debugging)
    
    -- Processing Timeline
    ingest_timestamp TIMESTAMP,  -- When did we receive this?
    prompt_sent_at TIMESTAMP,    -- When sent to LLM?
    response_received_at TIMESTAMP, -- When did LLM respond?
    structured_at TIMESTAMP,     -- When was it parsed?
    formatted_at TIMESTAMP,      -- When was email created?
    alert_sent_at TIMESTAMP,     -- When was it delivered?
    
    -- Intelligent Processing
    state alert_state,           -- Current processing stage
    prompt_type VARCHAR(50),     -- Which prompt approach?
    prompt_template TEXT,        -- Actual prompt used
    prompt_text TEXT,            -- Prompt with alert data
    
    -- LLM Interaction
    response_text TEXT,          -- Raw LLM response
    prompt_tokens INTEGER,       -- Cost tracking
    completion_tokens INTEGER,   -- Cost tracking
    total_tokens INTEGER,        -- Total API usage
    
    -- Parsing Results
    parser_used TEXT,            -- Which parser processed this?
    structured_data JSONB,       -- Parsed email structure
    
    -- Email Generation
    formatted_data JSONB,        -- Final email content
    email_recipients JSONB,      -- Who received this?
    email_error TEXT,            -- Any delivery issues?
    email_retry_count INTEGER    -- Delivery attempts
);
```


1. Agent Enricher (First in the pipeline)
This worker needs to:

Change from setting state to 'agent_enriched' to 'enriched'
Use the notification channel 'alert_enriched' instead of any old channel names
Properly set the enriched_at timestamp

2. LLM Worker (The current bottleneck)
This is your most critical fix because it's where everything is stuck. The worker needs to:

Listen for alerts in 'enriched' state (not 'agent_enriched')
Set the prompt_type field when selecting a prompt
Change state to 'analyzed' (not 'summarized') when complete
Notify on 'alert_analyzed' channel

3. Email Structurer (Parser)
This worker needs to:

Listen for 'alert_analyzed' notifications
Read the prompt_type field to select the appropriate parser
Set parser_used, parser_success, and related fields
Change state to 'structured' when complete
Notify on 'alert_structured' channel

4. Email Formatter
This worker needs to:

Listen for 'alert_structured' notifications
Change state to 'formatted' when complete
Notify on 'alert_formatted' channel

5. Email Sender
This worker needs to:

Listen for 'alert_formatted' notifications
Change state to 'sent' when complete
Use alert_sent_at instead of any old timestamp fields

## State Flow: Understanding Alert Lifecycle

Your alerts should flow through these states, with clear rules about progression:

```
NEW → AGENT_ENRICHED → RESPONDED → STRUCTURED → FORMATTED → SENT
 ↓         ↓              ↓            ↓           ↓          ↓
Can fail  Can fail    Can fail    Can fail    Can fail   Success!
and retry and retry   and retry   and retry   and retry
```

Each state represents a completed phase of processing. If an alert gets stuck, you know exactly where to look.

## Prompt Types: Your Communication Palette

### Security Analysis Format
**Purpose**: Detailed technical analysis for security teams
**When to use**: High-severity alerts, complex attacks, compliance events
**Key sections**: Threat Analysis, Technical Details, IoCs, Remediation Steps

### Executive Summary Format
**Purpose**: Business-focused summaries for leadership
**When to use**: Critical alerts, business hours, C-suite recipients
**Key sections**: Business Impact, Risk Assessment, Required Decisions

### Investigation Guide Format
**Purpose**: Step-by-step response procedures
**When to use**: Alerts requiring investigation, junior staff on duty
**Key sections**: Numbered Steps, Verification Procedures, Escalation Criteria

### Concise Notification Format
**Purpose**: Quick notifications for routine alerts
**When to use**: Low-severity alerts, high-volume periods
**Key sections**: What Happened, Why It Matters, What To Do

## Implementation Roadmap

### Step 1: Database Migration (Week 1)
First, ensure your database has all necessary columns. Run this check:

```sql
-- Check what's missing
SELECT column_name 
FROM information_schema.columns 
WHERE table_name = 'alerts' 
  AND column_name IN ('parser_success', 'parser_error', 'parser_duration_ms', 'agent_data');
```

If columns are missing, create a migration to add them.

### Step 2: Fix State Management (Week 1)
Your current states don't match the expected flow. Update your services to use the correct state names:

```python
# In each service, ensure consistent state usage
STATES = {
    'NEW': 'new',
    'AGENT_ENRICHED': 'agent_enriched',
    'RESPONDED': 'responded',
    'STRUCTURED': 'structured',
    'FORMATTED': 'formatted',
    'SENT': 'sent'
}
```

### Step 3: Implement Prompt Randomization (Week 2)
Update your LLM worker to properly set prompt types:

```python
def process_alert(alert_id):
    # Load available prompts
    prompts = load_prompt_configurations()
    
    # Select based on alert characteristics
    selected_prompt = select_prompt_intelligently(alert, prompts)
    
    # CRITICAL: Store the prompt type!
    cur.execute("""
        UPDATE alerts 
        SET prompt_type = %s,
            prompt_template = %s,
            state = 'responded'
        WHERE id = %s
    """, (selected_prompt.type, selected_prompt.template, alert_id))
```

### Step 4: Deploy Parser Registry (Week 2)
Ensure your email-structurer has all necessary parsers registered and can handle failures gracefully.

### Step 5: Monitoring & Optimization (Week 3)
Create dashboards to track:
- Parser success rates by prompt type
- Average processing times
- Circuit breaker states
- Alert volume by state

## Monitoring Queries for Daily Operations

### Health Check Dashboard
```sql
-- Overall pipeline health
CREATE VIEW pipeline_health AS
SELECT 
    COUNT(*) FILTER (WHERE state = 'new') as awaiting_enrichment,
    COUNT(*) FILTER (WHERE state = 'agent_enriched') as awaiting_llm,
    COUNT(*) FILTER (WHERE state = 'responded') as awaiting_parse,
    COUNT(*) FILTER (WHERE state = 'structured') as awaiting_format,
    COUNT(*) FILTER (WHERE state = 'formatted') as awaiting_send,
    COUNT(*) FILTER (WHERE state = 'sent') as completed_today
FROM alerts
WHERE ingest_timestamp > CURRENT_DATE;

-- Parser effectiveness
CREATE VIEW parser_effectiveness AS
SELECT 
    prompt_type,
    parser_used,
    COUNT(*) as attempts,
    COUNT(*) FILTER (WHERE structured_data IS NOT NULL) as successes,
    ROUND(AVG(EXTRACT(EPOCH FROM (structured_at - response_received_at))), 2) as avg_parse_seconds
FROM alerts
WHERE response_received_at > CURRENT_DATE - INTERVAL '7 days'
GROUP BY prompt_type, parser_used;
```

## Troubleshooting Playbook

### When Alerts Get Stuck

**Stuck in 'agent_enriched'**:
- Check: Is the LLM worker running?
- Check: Are you hitting OpenAI rate limits?
- Fix: Restart LLM worker, check API keys

**Stuck in 'responded'**:
- Check: Is prompt_type being set?
- Check: Is email-structurer running?
- Fix: Verify prompt_type is populated, restart structurer

**Circuit Breaker Open**:
- Check: Parser error patterns
- Check: LLM response format changes
- Fix: Update parser or prompt to match

## Success Metrics

Your pipeline is working optimally when:
- 95%+ of alerts complete within 5 minutes
- Parser success rate exceeds 90% for each prompt type
- No alerts remain stuck for more than 30 minutes
- Circuit breakers open less than once per week

## The Future State

Imagine your pipeline in six months:
- Machine learning selects optimal prompt types based on alert characteristics
- Parsers self-heal by analyzing successful parses
- Recipients can indicate preference for communication style
- The system learns which formats drive fastest remediation

This is not just an alert pipeline—it's an intelligent security communication system that adapts to your organization's needs.

Would you like me to create specific implementation scripts for any of these components, or help you diagnose why your current system is only using the `delphi_notify_short` parser?