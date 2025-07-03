# Delphi Pipeline Migration Implementation Plan

## Phase 1: Infrastructure Setup (Week 1)

### 1.1 Redis Installation & Configuration
```bash
# Install Redis on Ubuntu
sudo apt update
sudo apt install redis-server

# Configure Redis for production
sudo tee /etc/redis/redis.conf <<EOF
# Network
bind 127.0.0.1 ::1
port 6379
protected-mode yes

# Persistence
save 900 1
save 300 10
save 60 10000
dir /var/lib/redis
dbfilename delphi-dump.rdb

# Memory
maxmemory 2gb
maxmemory-policy allkeys-lru

# Streams configuration
stream-node-max-entries 100
stream-node-max-bytes 4096

# Logging
loglevel notice
logfile /var/log/redis/redis-server.log
EOF

# Enable and start Redis
sudo systemctl enable redis-server
sudo systemctl start redis-server
```

### 1.2 Environment Configuration
```bash
# Add to /opt/stackstorm/packs/delphi/.env
DELPHI_QUEUE_TYPE=hybrid
DELPHI_REDIS_ADDR=localhost:6379
DELPHI_REDIS_PASSWORD=
DELPHI_REDIS_DB=0
DELPHI_STREAM_NAME=delphi:alerts
DELPHI_CONSUMER_GROUP=delphi-workers
DELPHI_MAX_RETRIES=3
DELPHI_RETRY_BACKOFF=30s

# Circuit breaker configuration
DELPHI_ENABLE_CIRCUIT_BREAKERS=true
WAZUH_CB_FAILURE_THRESHOLD=5
WAZUH_CB_TIMEOUT=60s
LLM_CB_FAILURE_THRESHOLD=3
LLM_CB_TIMEOUT=120s
EMAIL_CB_FAILURE_THRESHOLD=5
EMAIL_CB_TIMEOUT=60s
```

## Phase 2: Hybrid Implementation (Week 2)

### 2.1 Create Integration Service
```go
// pkg/delphi/hybrid_worker.go
type HybridWorker struct {
    useRedis      bool
    streamHandler *StreamHandler
    pgNotifier    *PostgreSQLNotifier
    circuitMgr    *CircuitBreakerManager
    logger        *zap.Logger
}

func (hw *HybridWorker) PublishAlert(ctx context.Context, alert Alert) error {
    if hw.useRedis {
        return hw.publishToRedis(ctx, alert)
    }
    return hw.publishToPostgreSQL(ctx, alert)
}
```

### 2.2 Update Service Configuration
```systemd
# /etc/systemd/system/delphi-hybrid-listener.service
[Unit]
Description=Delphi Hybrid Alert Listener
After=network.target redis.service postgresql.service

[Service]
Type=notify
User=stanley
Group=stanley
Environment=DELPHI_QUEUE_TYPE=hybrid
Environment=DELPHI_ENABLE_CIRCUIT_BREAKERS=true
ExecStart=/opt/stackstorm/packs/delphi/delphi-hybrid-listener.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

## Phase 3: Worker Migration (Week 3)

### 3.1 Agent Enricher Migration
```python
# assets/python_workers/delphi-agent-enricher-v2.py
import asyncio
import redis.asyncio as redis
from circuit_breaker import CircuitBreaker

class AgentEnricherV2:
    def __init__(self):
        self.redis = redis.from_url(os.getenv('DELPHI_REDIS_URL'))
        self.wazuh_cb = CircuitBreaker('wazuh-api', 
            failure_threshold=5, timeout=60)
    
    async def process_alert(self, alert_data):
        try:
            async with self.wazuh_cb:
                agent_info = await self.get_agent_info(alert_data['agent_id'])
                return self.enrich_alert(alert_data, agent_info)
        except CircuitOpenError:
            logger.warning("Wazuh API circuit breaker open, using cached data")
            return self.use_cached_agent_info(alert_data)
```

### 3.2 LLM Processor Migration
```python
# assets/python_workers/email-structurer-v2.py
class EmailStructurerV2:
    def __init__(self):
        self.llm_cb = CircuitBreaker('llm-api', 
            failure_threshold=3, timeout=120)
        self.fallback_templates = self.load_fallback_templates()
    
    async def process_alert(self, alert_data):
        try:
            async with self.llm_cb:
                return await self.llm_analyze(alert_data)
        except CircuitOpenError:
            logger.warning("LLM circuit breaker open, using template")
            return self.template_response(alert_data)
```

## Phase 4: Testing & Validation (Week 4)

### 4.1 Load Testing Script
```python
#!/usr/bin/env python3
# scripts/load_test_delphi.py

import asyncio
import aiohttp
import time
import json
from datetime import datetime

async def generate_test_alerts(count=1000, rate=10):
    """Generate test alerts at specified rate"""
    async with aiohttp.ClientSession() as session:
        for i in range(count):
            alert = {
                "id": f"test-{i}",
                "timestamp": datetime.now().isoformat(),
                "rule": {"level": 10, "description": "Test alert"},
                "agent": {"id": "001", "name": "test-agent"}
            }
            
            await session.post(
                "http://localhost:9101/webhook",
                headers={"X-Auth-Token": "test-token"},
                json=alert
            )
            
            await asyncio.sleep(1.0 / rate)
```

### 4.2 Circuit Breaker Testing
```bash
#!/bin/bash
# scripts/test_circuit_breakers.sh

echo "Testing Wazuh API circuit breaker..."
# Stop Wazuh API
sudo systemctl stop wazuh-manager

# Send alerts and verify circuit opens
./load_test_delphi.py --count=10 --rate=5

# Check circuit breaker status
curl http://localhost:8080/health/circuit-breakers

# Restart Wazuh and verify recovery
sudo systemctl start wazuh-manager
```

## Phase 5: Production Rollout (Week 5)

### 5.1 Blue-Green Deployment
```bash
#!/bin/bash
# scripts/deploy_delphi_v2.sh

# Stop old services
systemctl stop delphi-agent-enricher
systemctl stop email-structurer
systemctl stop email-formatter
systemctl stop email-sender

# Deploy new services
cp assets/python_workers/*-v2.py /opt/stackstorm/packs/delphi/
cp assets/services/*-v2.service /etc/systemd/system/

# Update environment to use Redis
sed -i 's/DELPHI_QUEUE_TYPE=postgresql/DELPHI_QUEUE_TYPE=redis/' \
    /opt/stackstorm/packs/delphi/.env

# Start new services
systemctl daemon-reload
systemctl enable delphi-*-v2.service
systemctl start delphi-*-v2.service

# Monitor for 10 minutes
sleep 600

# Verify all services healthy
systemctl status delphi-*-v2.service
curl http://localhost:8080/health
```

### 5.2 Rollback Plan
```bash
#!/bin/bash
# scripts/rollback_delphi.sh

# Stop new services
systemctl stop delphi-*-v2.service

# Restore old environment
sed -i 's/DELPHI_QUEUE_TYPE=redis/DELPHI_QUEUE_TYPE=postgresql/' \
    /opt/stackstorm/packs/delphi/.env

# Start old services
systemctl start delphi-agent-enricher
systemctl start email-structurer
systemctl start email-formatter
systemctl start email-sender

echo "Rollback completed. Check service status:"
systemctl status delphi-*
```

## Monitoring & Alerting

### Dashboard Metrics
- Queue depth (Redis vs PostgreSQL)
- Processing latency by stage
- Circuit breaker states
- Error rates and retry counts
- Throughput (alerts/minute)

### Critical Alerts
- Circuit breaker opened (Slack notification)
- Queue depth > 1000 (Immediate notification)
- Processing latency > 5 minutes (Email alert)
- Redis connection lost (Immediate notification)

## Risk Assessment

### High Risk
- **Data loss during migration**: Mitigated by hybrid mode
- **Circuit breaker false positives**: Mitigated by tunable thresholds
- **Redis memory exhaustion**: Mitigated by TTL and LRU eviction

### Medium Risk  
- **Performance degradation**: Mitigated by load testing
- **Configuration drift**: Mitigated by infrastructure as code
- **Monitoring gaps**: Mitigated by comprehensive dashboards

### Low Risk
- **Service discovery issues**: Mitigated by static configuration
- **Network partitions**: Mitigated by PostgreSQL fallback

## Success Criteria

### Performance
- 10x throughput improvement (100 → 1000+ alerts/minute)
- 50% latency reduction (avg processing time)
- 99.9% availability during normal operations

### Reliability
- Zero data loss during migration
- < 30 second recovery time from failures
- Circuit breaker prevents cascade failures

### Operational
- Clear monitoring dashboards
- Automated alerting on failures
- Simple rollback procedure (< 5 minutes)