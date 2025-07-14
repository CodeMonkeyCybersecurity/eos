# Parser Health Monitoring

*Last Updated: 2025-01-14*

The `parser-monitor` service provides comprehensive observability for the Delphi prompt-aware parsing system.

## Overview

The parser monitoring dashboard tracks:
- **Parser Performance**: Success rates and timing by prompt type
- **Circuit Breaker Status**: Protection against cascading failures
- **Pipeline Health**: Alert flow through the processing stages
- **Error Analysis**: Recent failures and optimization recommendations

## Deployment

### 1. Install the Service

```bash
# Deploy the parser monitoring service
eos delphi services create parser-monitor

# Check installation
eos delphi services read parser-monitor
```

### 2. Access the Monitoring Dashboard

```bash
# Full monitoring dashboard
eos delphi parser-health

# Health summary only
eos delphi parser-health --health

# Live monitoring (refreshes every 30s)
eos delphi parser-health --continuous

# Specific views
eos delphi parser-health --performance      # Parser metrics
eos delphi parser-health --failures         # Recent failures
eos delphi parser-health --recommendations  # Optimization tips
eos delphi parser-health --circuit-breaker  # Circuit breaker status
```

### 3. Direct Script Access

```bash
# Run the monitoring script directly
/usr/local/bin/parser-monitor.py

# With specific options
/usr/local/bin/parser-monitor.py --continuous --interval 60
/usr/local/bin/parser-monitor.py --failures
```

## Dashboard Sections

###  Parser Health Summary
- Success rate over last 24 hours
- Average parse time
- Active prompt types
- Stuck alerts (waiting >1 hour)

###  Pipeline Status
Shows alert counts by processing state:
- `summarized` → Ready for structuring
- `structured` → Ready for formatting  
- `formatted` → Ready for sending
- `sent` → Successfully delivered

###  Circuit Breaker Status
Monitors parser reliability:
- 🟢 **CLOSED**: Normal operation
- 🟡 **HALF_OPEN**: Recent failures, monitoring
- 🔴 **OPEN**: Parser disabled due to failures

###  Parser Performance
Metrics by prompt type:
- Total attempts
- Success rate percentage
- Average parsing time
- Last used timestamp

###  Prompt Type Distribution
Shows usage patterns:
- Alert counts by prompt type
- End-to-end success rates
- Average processing time

###  Recent Parser Failures
Lists recent parsing errors with:
- Alert ID and prompt type
- Parser used
- Error details
- Timestamp

###  Parser Effectiveness Analysis
Identifies optimization opportunities:
- Parser/prompt type mismatches
- Recommended parser changes
- Failure frequency analysis

## Configuration

The service uses these environment variables:

```bash
# In /opt/stackstorm/packs/delphi/.env
PG_DSN=postgresql://user:pass@host:5432/delphi

# Optional: Monitor configuration
MONITOR_DASHBOARD_MODE=health
MONITOR_OUTPUT_FORMAT=text
```

## Monitoring Queries

### Manual Database Analysis

```sql
-- Parser success rates by prompt type
SELECT 
    prompt_type,
    COUNT(*) as total,
    COUNT(*) FILTER (WHERE success) as successful,
    ROUND((COUNT(*) FILTER (WHERE success)::decimal / COUNT(*)) * 100, 2) as success_rate
FROM parser_metrics
WHERE created_at > NOW() - INTERVAL '24 hours'
GROUP BY prompt_type
ORDER BY success_rate DESC;

-- Recent parser failures
SELECT 
    alert_id,
    prompt_type,
    parser_used,
    error,
    created_at
FROM parser_metrics
WHERE success = FALSE
  AND created_at > NOW() - INTERVAL '1 hour'
ORDER BY created_at DESC;

-- Circuit breaker analysis
SELECT 
    prompt_type,
    COUNT(*) FILTER (WHERE NOT success AND created_at > NOW() - INTERVAL '1 hour') as recent_failures,
    MAX(created_at) FILTER (WHERE NOT success) as last_failure
FROM parser_metrics
WHERE created_at > NOW() - INTERVAL '24 hours'
GROUP BY prompt_type
HAVING COUNT(*) FILTER (WHERE NOT success) > 0;
```

## Alerting Integration

### Set up monitoring alerts:

```bash
# Check for stuck alerts
/usr/local/bin/parser-monitor.py --health | grep "Stuck Alerts" | awk '{print $3}' > /tmp/stuck_count
if [ $(cat /tmp/stuck_count) -gt 10 ]; then
    echo "WARNING: $(cat /tmp/stuck_count) alerts stuck in pipeline"
fi

# Check circuit breaker status
/usr/local/bin/parser-monitor.py --circuit-breaker | grep "OPEN" && \
    echo "CRITICAL: Parser circuit breaker is OPEN"

# Check success rate
/usr/local/bin/parser-monitor.py --health | grep "Success Rate" | \
    awk '{if ($4 < 90) print "WARNING: Parser success rate below 90%: " $4}'
```

## Troubleshooting

### Common Issues

**High Parser Failure Rate**
1. Check recent failures: `eos delphi parser-health --failures`
2. Review prompt/parser mismatches: `eos delphi parser-health --recommendations`
3. Check database connectivity and prompt_type assignment

**Circuit Breaker Open**
1. Wait for 5-minute timeout to reset
2. Check underlying parsing issues
3. Review prompt format changes
4. Verify parser registry mappings

**Stuck Alerts**
1. Check email-structurer service status: `systemctl status email-structurer`
2. Review service logs: `journalctl -f -u email-structurer`
3. Check database notification channels

**Performance Issues**
1. Monitor parse times: `eos delphi parser-health --performance`
2. Check for complex regex patterns in parsers
3. Review database query performance
4. Consider parser optimization

### Log Files

```bash
# Parser monitor logs
tail -f /var/log/stackstorm/parser-monitor.log

# Email structurer logs (shows parser selection)
journalctl -f -u email-structurer

# Database query logs
tail -f /var/log/postgresql/postgresql-*.log | grep parser_metrics
```

## Dependencies

The parser-monitor service requires:
- Python 3 with `psycopg2`, `tabulate`, `python-dotenv`
- PostgreSQL database with parser_metrics table
- Access to Delphi database via PG_DSN

Install dependencies:
```bash
pip3 install psycopg2-binary tabulate python-dotenv
```

---

This monitoring system provides comprehensive visibility into your prompt-aware parsing pipeline, enabling proactive identification and resolution of performance issues.