# BionicGPT Deployment Quick Reference

*Last Updated: 2025-10-22*

## Quick Start (With Shift-Left Fixes)

```bash
# One command deployment - fully automated
sudo eos create bionicgpt \
  --azure-endpoint https://YOUR_RESOURCE.openai.azure.com \
  --azure-chat-deployment gpt-4 \
  --azure-embeddings-deployment text-embedding-ada-002 \
  --azure-api-key $AZURE_KEY
```

**Expected Outcome**:
- ✓ Pre-flight validation passes (configuration, ports, docker, disk space)
- ✓ Phased deployment completes all 6 phases (database → migrations → services → proxy → rag → app)
- ✓ Post-deployment verification confirms all systems healthy
- ✓ Web interface accessible at http://localhost:8513
- ✓ Total time: <5 minutes, zero manual intervention

---

## What Happens During Deployment

### 1. Pre-Flight Validation (5-10 seconds)
```
Checking:
- Configuration completeness ✓
- Port availability (8513, 4000) ✓
- Docker daemon health ✓
- Disk space (min 10GB) ✓
- Azure OpenAI config ✓
```

If any check fails → immediate error with remediation steps, deployment aborted.

### 2. Configuration & Secrets (10-20 seconds)
```
- Discover environment (Vault integration)
- Retrieve/generate secrets from Vault:
  • postgres_password
  • jwt_secret
  • litellm_master_key
  • azure_api_key (if not provided)
- Create database init script (automatic user creation)
- Generate .env and docker-compose.yml files
- Create LiteLLM configuration
```

### 3. Phased Deployment (~3-4 minutes)
```
Phase 1: Database (20s)
  ├─ Start postgres container
  ├─ Init script automatically creates bionic_application user
  └─ Verify health check passes

Phase 2: Migrations (30s)
  ├─ Run database migrations
  └─ Schema setup complete

Phase 3: Supporting Services (15s)
  ├─ Start embeddings-api
  └─ Start chunking-engine

Phase 4: LiteLLM Proxy (90s)
  ├─ Start litellm-proxy
  ├─ Connect to Azure OpenAI (may take 60s)
  └─ Verify health check passes (tolerant config)

Phase 5: RAG Engine (15s)
  └─ Start rag-engine (document processing)

Phase 6: Application (30s)
  ├─ Start app container
  └─ Verify web interface accessible
```

### 4. Post-Deployment Verification (20-30 seconds)
```
Checking:
- All containers running ✓
- Database user exists ✓
- LiteLLM proxy responding ✓
- Web interface accessible ✓
- Health endpoints working ✓
- No errors in logs ✓
```

If any check fails → warning with specific issue, but deployment doesn't fail (services may need more time).

---

## Deployment Artifacts

After successful deployment, you'll find:

```
/opt/bionicgpt/
├── docker-compose.yml        # Generated compose file
├── .env                       # Main environment configuration
├── .env.litellm              # LiteLLM proxy configuration
├── litellm_config.yaml       # LiteLLM model routing
└── init-db.sh                # Database initialization script (auto-creates user)
```

---

## Common Scenarios

### Scenario 1: First Time Installation
```bash
# Install with Azure OpenAI
sudo eos create bionicgpt

# You will be prompted for:
# - Embeddings backend (Azure or local Ollama)
# - Azure endpoint
# - Azure deployment names
# - API key (or retrieved from Vault)

# Expected: Deployment completes in <5 minutes
# Access: http://localhost:8513
```

### Scenario 2: Reinstallation / Upgrade
```bash
# Force reinstall (wipes existing data)
sudo eos create bionicgpt --force

# Or manually teardown first:
cd /opt/bionicgpt
sudo docker compose down -v  # Remove volumes
sudo eos create bionicgpt
```

### Scenario 3: Local Embeddings (Free)
```bash
# Use Ollama for embeddings instead of Azure
sudo eos create bionicgpt --use-local-embeddings

# Requires Ollama installed and running
# Will automatically pull nomic-embed-text model (~274MB)
```

### Scenario 4: Custom Port
```bash
# Use different port (e.g., if 8513 in use)
sudo eos create bionicgpt --port 9000
```

---

## Troubleshooting

### Pre-Flight Check Failed

**Error**: "Port 8513 already in use"
```bash
# Check what's using the port
sudo ss -tlnp | grep 8513

# If it's old BionicGPT:
cd /opt/bionicgpt
sudo docker compose down

# Then retry deployment
```

**Error**: "Docker daemon not running"
```bash
sudo systemctl start docker
sudo systemctl enable docker
```

**Error**: "Insufficient disk space"
```bash
# Check available space
df -h /opt

# Clean up docker if needed
sudo docker system prune -a
```

### Deployment Phase Failed

**Phase 1 (Database) Fails**
```bash
# Check postgres logs
docker logs bionicgpt-postgres

# Common issues:
# - Volume permissions
# - Port 5432 already in use (internal)
```

**Phase 4 (LiteLLM) Fails**
```bash
# Check LiteLLM logs
docker logs bionicgpt-litellm

# Common issues:
# - Invalid Azure API key
# - Wrong deployment names
# - Network connectivity to Azure
# - Azure rate limits

# Verify Azure config manually:
docker exec bionicgpt-litellm cat /app/config.yaml
docker exec bionicgpt-litellm env | grep AZURE
```

**Phase 6 (App) Fails**
```bash
# Check app logs
docker logs bionicgpt-app

# Common issues:
# - Database connection (check bionic_application user exists)
# - JWT secret not set
# - LiteLLM proxy not responding
```

### Post-Deployment Verification Warnings

If verification shows warnings (not errors), services may still be starting. Wait 2-3 minutes and check:

```bash
# Check all containers
docker ps | grep bionicgpt

# Check specific container health
docker inspect bionicgpt-app --format='{{.State.Health.Status}}'
docker inspect bionicgpt-litellm --format='{{.State.Health.Status}}'

# Test web interface
curl http://localhost:8513
```

---

## Manual Verification Commands

```bash
# Check all containers running
docker ps | grep bionicgpt

# Check health status
docker inspect bionicgpt-app --format='{{.State.Health.Status}}'
docker inspect bionicgpt-postgres --format='{{.State.Health.Status}}'
docker inspect bionicgpt-litellm --format='{{.State.Health.Status}}'

# Verify database user exists
docker exec bionicgpt-postgres psql -U postgres -d bionic-gpt \
  -c "SELECT usename FROM pg_user WHERE usename='bionic_application';"

# Test LiteLLM proxy
curl http://localhost:4000/health

# Test web interface
curl http://localhost:8513

# Check logs
docker logs bionicgpt-app --tail 50
docker logs bionicgpt-litellm --tail 50
docker logs bionicgpt-postgres --tail 50
```

---

## Access & Usage

### First Access
1. Open browser: `http://localhost:8513`
2. Create your first team
3. Configure users and permissions
4. Upload documents for RAG functionality

### LiteLLM Proxy Access (for debugging)
- Health endpoint: `http://localhost:4000/health`
- Admin UI: `http://localhost:4000/ui` (if enabled)
- API: `http://localhost:4000/v1/...`

### Database Access
```bash
# Connect as application user
docker exec -it bionicgpt-postgres psql \
  -U bionic_application -d bionic-gpt

# Connect as postgres superuser
docker exec -it bionicgpt-postgres psql \
  -U postgres -d bionic-gpt
```

---

## Operational Commands

```bash
# View logs (all services)
docker compose -f /opt/bionicgpt/docker-compose.yml logs -f

# View logs (specific service)
docker logs bionicgpt-app -f

# Restart all services
docker compose -f /opt/bionicgpt/docker-compose.yml restart

# Restart specific service
docker restart bionicgpt-app

# Stop services
docker compose -f /opt/bionicgpt/docker-compose.yml down

# Stop and remove volumes (DESTRUCTIVE)
docker compose -f /opt/bionicgpt/docker-compose.yml down -v

# Check service status
docker compose -f /opt/bionicgpt/docker-compose.yml ps

# View resource usage
docker stats bionicgpt-app bionicgpt-postgres bionicgpt-litellm
```

---

## Shift-Left Improvements Reference

### What's New (Compared to Previous Version)

1. **Pre-Flight Validation** - Catches issues before deployment starts
2. **Automated Database User Creation** - No manual SQL commands needed
3. **Improved Health Checks** - LiteLLM has more tolerant configuration (90s start period, 5 retries)
4. **Phased Deployment** - Services start in correct order with verification
5. **Post-Deployment Verification** - Immediate confirmation everything works

### Key Files Created Automatically
- `/opt/bionicgpt/init-db.sh` - Database user creation script (NEW)
  - Automatically executed by postgres on first startup
  - Creates `bionic_application` user with correct permissions
  - Idempotent (safe to run multiple times)

### Docker Compose Changes
- **Postgres**: Added init script volume mount
- **LiteLLM**: Updated health check (90s start_period, 5 retries, 60s interval)
- **All**: Better logging configuration

---

## Performance Benchmarks

### Deployment Time
- **Full deployment**: 3-5 minutes (automated)
- **Pre-flight validation**: 5-10 seconds
- **Phased deployment**: 3-4 minutes
- **Post-deployment verification**: 20-30 seconds

### Resource Usage
- **Memory**: ~4GB total (all containers)
- **Disk**: ~10GB (images + volumes)
- **CPU**: 2+ cores recommended

---

## Support & Diagnostics

```bash
# Run comprehensive diagnostics
sudo eos debug bionicgpt

# Check specific issues
docker logs bionicgpt-app | grep -i error
docker logs bionicgpt-litellm | grep -i error

# Export deployment state for support
docker compose -f /opt/bionicgpt/docker-compose.yml config > deployment-state.yml
docker ps -a > containers-state.txt
```

---

## Related Documentation

- Full shift-left analysis: `SHIFT_LEFT_FIXES_SUMMARY.md`
- Eos architecture: `CLAUDE.md`
- BionicGPT official docs: https://bionic-gpt.com/docs/

---

*Code Monkey Cybersecurity - "Cybersecurity. With humans."*
