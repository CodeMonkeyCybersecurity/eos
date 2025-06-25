# Prompt-Aware Parsing Integration Guide

This document explains how to integrate the new prompt-aware parsing system into your existing Delphi pipeline.

## 🎯 Quick Start

The new system allows each alert to use a different prompt format and automatically selects the appropriate parser based on the `prompt_type` stored in the database.

### Step 1: Update Your Prompt Randomizer

Your existing prompt randomizer needs to store the `prompt_type` when assigning prompts to alerts.

**Example Update to Prompt Randomizer:**

```python
# OLD CODE (example)
def assign_random_prompt(alert_id: int):
    prompts = [
        load_prompt_file('delphi-notify-short.txt'),
        load_prompt_file('security-analysis.txt'), 
        load_prompt_file('numbered-investigation.txt')
    ]
    selected_prompt = random.choice(prompts)
    
    # Store only the prompt text
    update_alert_prompt(alert_id, selected_prompt)

# NEW CODE (recommended)
def assign_random_prompt(alert_id: int):
    prompt_configs = [
        {
            'type': 'delphi_notify_short',
            'file': 'delphi-notify-short.txt',
            'description': 'Concise 300-word security notifications'
        },
        {
            'type': 'security_analysis', 
            'file': 'security-analysis.txt',
            'description': 'Detailed threat analysis format'
        },
        {
            'type': 'numbered_investigation',
            'file': 'numbered-investigation.txt', 
            'description': 'Step-by-step investigation format'
        }
    ]
    
    selected_config = random.choice(prompt_configs)
    prompt_text = load_prompt_file(selected_config['file'])
    
    # Store both prompt type and text
    with conn.cursor() as cur:
        cur.execute("""
            UPDATE alerts 
            SET prompt_type = %s,
                prompt_template = %s,
                prompt_text = %s
            WHERE id = %s
        """, (
            selected_config['type'],
            selected_config['file'], 
            prompt_text,
            alert_id
        ))
    
    log.info("Assigned prompt type '%s' to alert %d", 
             selected_config['type'], alert_id)
```

### Step 2: Create Prompt Files for Each Type

Store your prompt templates in `/srv/eos/system-prompts/` with clear naming:

```bash
# Example prompt files
/srv/eos/system-prompts/
├── delphi-notify-short.txt          # Your existing short format
├── security-analysis.txt            # New security-focused format  
├── numbered-investigation.txt       # New numbered list format
└── executive-summary.txt            # Optional executive format
```

### Step 3: Map Prompt Files to Parser Types

Update your prompt configuration to explicitly map files to parser types:

```python
# In your prompt randomizer configuration
PROMPT_TYPE_MAPPING = {
    'delphi-notify-short.txt': 'delphi_notify_short',
    'security-analysis.txt': 'security_analysis', 
    'numbered-investigation.txt': 'numbered_investigation',
    'executive-summary.txt': 'hybrid',  # Use fallback parser
}

def get_prompt_type_from_file(filename: str) -> str:
    """Get parser type from prompt filename"""
    return PROMPT_TYPE_MAPPING.get(filename, 'delphi_notify_short')
```

##  Monitoring Integration

### View Parser Performance

```sql
-- Check parser success rates by prompt type
SELECT * FROM parser_performance;

-- Monitor prompt usage distribution  
SELECT * FROM prompt_usage_stats;

-- Get real-time parser health
SELECT * FROM get_parser_health('1 hour'::INTERVAL);
```

### Example Monitoring Queries

```sql
-- Alerts that failed parsing in the last hour
SELECT 
    id, prompt_type, parser_used, parser_error, created_at
FROM alerts 
WHERE parser_success = FALSE 
  AND created_at > NOW() - INTERVAL '1 hour'
ORDER BY created_at DESC;

-- Average processing time by prompt type
SELECT 
    prompt_type,
    COUNT(*) as total_alerts,
    AVG(parser_duration_ms) as avg_duration_ms,
    MAX(parser_duration_ms) as max_duration_ms
FROM alerts 
WHERE parser_duration_ms IS NOT NULL
  AND created_at > NOW() - INTERVAL '24 hours'
GROUP BY prompt_type
ORDER BY avg_duration_ms DESC;

-- Identify problematic prompts
SELECT 
    prompt_type,
    COUNT(*) as total,
    SUM(CASE WHEN parser_success THEN 1 ELSE 0 END) as successful,
    ROUND((SUM(CASE WHEN parser_success THEN 1 ELSE 0 END)::decimal / COUNT(*)) * 100, 2) as success_rate
FROM alerts 
WHERE created_at > NOW() - INTERVAL '7 days'
  AND prompt_type IS NOT NULL
GROUP BY prompt_type
HAVING COUNT(*) >= 10  -- Only show prompts with enough data
ORDER BY success_rate ASC;
```

## 🛠️ Custom Parser Development

### Adding a New Parser

1. **Create the parser class in `parser_registry.py`:**

```python
class ExecutiveSummaryParser(ResponseParser):
    """Parser for executive summary format"""
    
    def get_expected_sections(self) -> List[str]:
        return ["Executive Summary", "Risk Level", "Business Impact", "Recommended Actions"]
    
    def parse(self, response_text: str) -> Dict[str, str]:
        # Your parsing logic here
        sections = {}
        # ... implementation
        return sections
```

2. **Register the parser:**

```python
# In parser_registry.py
def _register_default_parsers(self):
    # ... existing registrations
    self.register('executive_summary', ExecutiveSummaryParser)
```

3. **Create the prompt template:**

```text
# /srv/eos/system-prompts/executive-summary.txt
You are creating an executive summary for senior leadership. Analyze this security alert and provide:

Executive Summary: One paragraph overview for executives
Risk Level: [LOW/MEDIUM/HIGH/CRITICAL] with business justification  
Business Impact: Potential impact on operations, revenue, reputation
Recommended Actions: Priority-ordered list of business decisions needed

Keep technical details minimal. Focus on business implications.
```

4. **Update your prompt randomizer:**

```python
prompt_configs.append({
    'type': 'executive_summary',
    'file': 'executive-summary.txt',
    'description': 'Executive-focused business impact analysis'
})
```

## 🔧 Environment Configuration

### Email Structurer Environment Variables

```bash
# Parser configuration
DELPHI_PARSER_TYPE=auto                    # Use prompt_type from database
DELPHI_CUSTOM_SECTIONS=                    # For custom parser (comma-separated)

# Database connection  
PG_DSN=postgresql://user:pass@host:5432/delphi

# Channels
LISTEN_CHANNEL=alert_to_structure          # Channel to listen on
NOTIFY_CHANNEL=alert_structured            # Channel to notify when done
```

### Service Dependencies

The email-structurer now requires:
- `parser_registry.py` in the same directory (`/usr/local/bin/`)
- Database schema migration `002_add_prompt_tracking.sql` applied
- Updated prompt randomizer storing `prompt_type`

## 🚨 Troubleshooting

### Common Issues

**1. Parser Not Found**
```
WARNING: No parser registered for prompt_type: 'my_custom_type', using fallback
```
**Solution:** Register your parser in `parser_registry.py` or use an existing prompt type.

**2. Validation Failures**
```
WARNING: Primary parser failed validation for alert 123, trying fallback
```
**Solution:** Check that your prompt generates the expected section headers.

**3. Database Errors**
```
ERROR: column "prompt_type" does not exist
```
**Solution:** Run the database migration `002_add_prompt_tracking.sql`.

### Debug Mode

Enable detailed logging for parser troubleshooting:

```python
# In email-structurer.py, add this to setup_logging()
logger.setLevel(logging.DEBUG)

# Or set environment variable
LOG_LEVEL=DEBUG
```

### Parser Testing

Test parsers before deployment:

```python
# Test script example
from parser_registry import get_parser_for_prompt

# Load sample LLM response
with open('sample_response.txt') as f:
    sample_response = f.read()

# Test parser
parser = get_parser_for_prompt('delphi_notify_short')
sections = parser.parse(sample_response)

print(f"Extracted {len(sections)} sections:")
for section, content in sections.items():
    print(f"  {section}: {content[:100]}...")
```

## 📈 Performance Optimization

### Parser Performance Tips

1. **Profile your parsers:** Use the `parser_duration_ms` metrics to identify slow parsers
2. **Optimize regex patterns:** Complex regex can slow down parsing significantly  
3. **Use circuit breakers:** The system automatically disables failing parsers temporarily
4. **Monitor validation rates:** Low validation rates indicate prompt/parser mismatches

### Database Optimization

```sql
-- Add indexes for common queries
CREATE INDEX CONCURRENTLY idx_alerts_prompt_performance 
ON alerts (prompt_type, parser_success, created_at);

-- Partition parser_metrics by date for high-volume deployments
-- (Advanced - only for >1M alerts/day)
```

## 🔄 Migration Path

### Gradual Rollout Strategy

1. **Phase 1:** Deploy new email-structurer alongside existing one
2. **Phase 2:** Update 10% of alerts to use new prompt types
3. **Phase 3:** Monitor parser performance and fix issues
4. **Phase 4:** Migrate remaining alerts to prompt-aware system
5. **Phase 5:** Remove old email-structurer code

### Rollback Plan

If issues arise:

```sql
-- Temporarily disable prompt-aware parsing
UPDATE alerts SET prompt_type = 'delphi_notify_short' 
WHERE prompt_type IS NULL OR parser_success = FALSE;

-- Or revert to old structurer by removing prompt_type
UPDATE alerts SET prompt_type = NULL 
WHERE created_at > NOW() - INTERVAL '1 day';
```

---

This integration maintains backward compatibility while enabling powerful new parsing capabilities. The system gracefully degrades to fallback parsers when issues occur, ensuring reliable email delivery.