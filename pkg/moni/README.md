# pkg/moni - Moni (BionicGPT) Initialization Worker

*Last Updated: 2025-01-07*

This package implements the Moni (BionicGPT) initialization worker, handling SSL certificate generation, database configuration, security hardening, and verification for multi-tenant LLM deployments.

## Architecture

### Core Files

- **worker.go** (813 lines) - Main orchestration with 9-phase setup flow
- **ssl.go** (465 lines) - SSL certificate generation + SHIFT-LEFT v2 testing
- **database.go** (399 lines) - Database config + security hardening + RLS
- **verification.go** (577 lines) - Health checks + security verification
- **types.go** (107 lines) - Type definitions (WorkerConfig, SetupResult, etc.)
- **constants.go** (88 lines) - Configuration constants (paths, UIDs, timeouts)

### Total: ~2,449 lines of production Go code

## Features

### 9-Phase Setup Flow

1. **Phase 1: SSL Certificate Generation**
   - Generates self-signed certificates for PostgreSQL
   - Checks existing certificates for validity (365-day expiration)
   - Creates `/opt/moni/certs/` directory structure

2. **Phase 2: Certificate Permission Validation**
   - **SHIFT-LEFT v2 Testing**: Validates certificates are readable BEFORE deployment
   - Detects Alpine (UID 70) vs Standard (UID 999) PostgreSQL images
   - Implements multi-strategy certificate management:
     - Single UID 70 (Alpine-only)
     - Single UID 999 (Standard-only)
     - Separate certs (Mixed Alpine + Standard)
   - Sets correct ownership: `0:70` or `999:999`
   - Sets correct permissions: `640` for keys, `644` for certs

3. **Phase 3: Environment Configuration**
   - Updates `.env` to enable SSL (`sslmode=disable` → `sslmode=require`)
   - Creates timestamped backups with `0600` permissions
   - Cleans up old backups (keeps last 3)

4. **Phase 4: Container Restart**
   - Stops containers: `docker compose down`
   - Starts with new config: `docker compose up -d`
   - Waits 30 seconds for initialization
   - Thread-safe: Uses `WorkDir` instead of `os.Chdir()`

5. **Phase 5: Database Configuration**
   - **Upserts 3 models**:
     - `nomic-embed-text` (Embeddings, 8192 context)
     - `Moni` (LLM, GPT-5-mini, 16384 max tokens)
     - `Moni-4.1` (LLM, GPT-4.1-mini, 16384 max tokens)
   - **Renames default assistant**: `llama3` → `Moni`
   - Links Moni prompt to Moni model (ID 2)

6. **Phase 6: API Key Regeneration**
   - Runs `/opt/moni/api_keys.sh` if present
   - Generates new LiteLLM virtual keys
   - Updates `.env` and database

7. **Phase 7: Database Security Hardening**
   - **Least Privilege**:
     - `litellm`: NOSUPERUSER, DML only (no DDL)
     - `bionic_application`: DML only (no schema changes)
     - `bionic_readonly`: Created for monitoring (read-only)
   - **Row Level Security (RLS)**:
     - Enables RLS on 15 critical tables
     - Creates tenant isolation policies
     - **P0 SECURITY FIX**: Fails loudly if `app.current_team_id` not set
     - Verifies `bionic_application` is NOT a superuser (P0 check)

8. **Phase 8: Security Verification**
   - **RLS Verification**:
     - Checks 15 tables have RLS enabled
     - Verifies policies exist
     - **P1 PERFORMANCE**: Checks for `team_id` indexes
   - **CSP Verification**:
     - Checks Content-Security-Policy headers
     - Scores 0-100 based on security directives
     - Detects dangerous patterns (`'unsafe-eval'`, wildcards)

9. **Phase 9: Final Health Check**
   - Verifies PostgreSQL SSL status
   - Checks LiteLLM models endpoint
   - Validates web search configuration
   - Confirms all containers healthy

## Security Implementation

### Row Level Security (RLS)

**Protected Tables** (15 total):
- **Direct team_id** (12): api_key_connections, api_keys, audit_trail, conversations, datasets, document_pipelines, integrations, invitations, oauth2_connections, objects, prompts, team_users
- **Indirect team_id** (3): chats, documents, chunks

**Policy Pattern**:
```sql
CREATE POLICY tenant_isolation_<table> ON <table>
    FOR ALL TO bionic_application
    USING (team_id = current_setting('app.current_team_id')::int);
```

**P0 SECURITY FIX**: Removed `true` parameter from `current_setting()` to fail loudly if session variable not set.

**CRITICAL REQUIREMENT**: Application MUST set `app.current_team_id` on every connection:
```sql
SET app.current_team_id = <user's team ID>;
```

Without this, queries will ERROR (intentional - fail loudly, not silently).

### SSL Certificate Management

**Alpine PostgreSQL** (postgres:*-alpine, pgvector/pgvector:*-alpine):
- UID: 70 (postgres group)
- Ownership: `0:70` (root:postgres)
- Permissions: `640` (owner RW, group R)

**Standard PostgreSQL** (postgres:*, pgvector/pgvector:*):
- UID: 999 (postgres user)
- Ownership: `999:999` (postgres:postgres)
- Permissions: `600` (owner RW only)

**SHIFT-LEFT v2 Testing**:
```go
TestCertReadability(rc, image, uid, certPath)
```
Validates certificates are readable by running test containers BEFORE deployment.

### Database Hardening

**litellm user**:
```sql
ALTER USER litellm NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO litellm;
```

**bionic_application user**:
```sql
REVOKE ALL ON DATABASE "bionic-gpt" FROM bionic_application;
GRANT CONNECT ON DATABASE "bionic-gpt" TO bionic_application;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO bionic_application;
```

**bionic_readonly user**:
```sql
CREATE USER bionic_readonly WITH PASSWORD '<postgres_password>';
GRANT CONNECT ON DATABASE "bionic-gpt" TO bionic_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO bionic_readonly;
```

## Usage

### Command Integration

Integrated into `cmd/update/moni.go` as `eos update moni` command.

### Full Initialization

```bash
sudo eos update moni --init
```

Runs all 9 phases.

### Targeted Operations

```bash
# Certificate operations
sudo eos update moni --validate-certs    # SHIFT-LEFT v2 testing
sudo eos update moni --fix-certs         # Fix permissions

# Security verification
sudo eos update moni --verify-security   # RLS + CSP
sudo eos update moni --verify-rls        # Row Level Security only
sudo eos update moni --verify-csp        # Content Security Policy only

# Database operations
sudo eos update moni --verify-db         # Verify models/prompts

# Maintenance
sudo eos update moni --cleanup-backups   # Clean old .env backups
```

### Phase Control

```bash
# Skip specific phases
sudo eos update moni --init --skip-ssl
sudo eos update moni --init --skip-database
sudo eos update moni --init --skip-security
sudo eos update moni --init --skip-verification
```

### Custom Working Directory

```bash
sudo eos update moni --init --work-dir /opt/custom-moni
```

## Configuration

### Constants (constants.go)

**Paths**:
- `MoniDir`: `/opt/moni`
- `MoniEnvFile`: `/opt/moni/.env`
- `MoniCertsDir`: `/opt/moni/certs`
- `MoniDockerCompose`: `/opt/moni/docker-compose.yml`

**Timeouts**:
- `MaxWaitSeconds`: 120s (service readiness)
- `CheckIntervalSecs`: 2s (health check polling)
- `CommandTimeout`: 30s (SQL, docker exec)
- `LongCommandTimeout`: 5m (API key regeneration)

**SSL Certificate**:
- `CertOwnerUID`: 0 (root)
- `CertOwnerGID`: 70 (Alpine postgres group)
- `StandardUID`: 999 (Standard postgres user)
- `CertKeyPerms`: 0640
- `CertCrtPerms`: 0644

**Model Configuration**:
- `ModelContextSize`: 16384 (max completion tokens)
- `EmbeddingsContextSize`: 8192

### Environment Variables

Required in `/opt/moni/.env`:
- `POSTGRES_PASSWORD` - PostgreSQL root password
- `LITELLM_MASTER_KEY` - LiteLLM master API key
- `APP_DATABASE_URL` - BionicGPT database connection string

Optional:
- `ENABLE_WEB_SEARCH` - Enable web search (`true`/`false`)
- `MONI_SYSTEM_PROMPT` - Custom system prompt

## Error Handling

### User-Fixable Errors (Exit 0)

- Missing prerequisites (Docker, OpenSSL, curl, sudo)
- Working directory doesn't exist
- docker-compose.yml not found

**Returns**: Clear error with remediation steps

### System Failures (Exit 1)

- SSL certificate generation failed
- Docker Compose operations failed
- Database hardening failed
- RLS enablement failed

**Returns**: Error with context and troubleshooting steps

## Pattern Compliance

✅ **Logging**: Uses `otelzap.Ctx(rc.Ctx)` everywhere
✅ **Architecture**: Business logic in `pkg/moni/`, orchestration in `cmd/`
✅ **AIE Pattern**: All functions follow Assess→Intervene→Evaluate
✅ **RuntimeContext**: Passed to all operations
✅ **Constants**: No hardcoded values (all in constants.go)
✅ **Thread-Safe**: Uses `execute.Options.WorkDir` instead of `os.Chdir()`
✅ **Error Context**: All errors include remediation steps

## Testing

### Prerequisites Check

```go
checkPrerequisites(rc) error
```

Validates:
- Docker CLI available
- Docker daemon responding
- Docker Compose available
- OpenSSL available
- sudo available
- curl available

### Container Health Check

```go
checkContainerHealth(rc) error
```

Detects unhealthy containers and logs last 10 lines of logs.

### Service Readiness

```go
WaitForService(rc, name, checkFunc, maxWait, checkInterval) error
```

Polls until service ready or timeout:
- PostgreSQL: `pg_isready -U postgres`
- LiteLLM: `curl -sf http://localhost:4000/health/readiness`

## Troubleshooting

### SSL Certificate Issues

**Symptom**: PostgreSQL fails to start with "certificate permission denied"

**Fix**:
```bash
sudo eos update moni --fix-certs
```

**Verify**:
```bash
sudo eos update moni --validate-certs
```

### RLS Not Working

**Symptom**: Users see all data across tenants OR users see no data

**Check**:
```bash
sudo eos update moni --verify-rls
```

**Fix**: Ensure application sets `app.current_team_id`:
```sql
-- In connection initialization
SET app.current_team_id = <user's team_id>;
```

### Performance Issues

**Symptom**: Slow queries after enabling RLS

**Check**:
```bash
sudo eos update moni --verify-rls
```

Look for warnings about missing `team_id` indexes.

**Fix** (if indexes missing):
```sql
CREATE INDEX idx_<table>_team_id ON <table>(team_id);
```

### Container Startup Failures

**Check logs**:
```bash
docker compose -f /opt/moni/docker-compose.yml logs -f
```

**Check health**:
```bash
docker ps -a
```

**Restart with fresh config**:
```bash
sudo eos update moni --init --skip-database --skip-security
```

## Best Practices

### Production Deployment

1. ✅ Run `--init` on fresh installation
2. ✅ Verify RLS with `--verify-rls`
3. ✅ Verify CSP with `--verify-csp`
4. ✅ Ensure application sets `app.current_team_id`
5. ✅ Monitor container health
6. ✅ Create `team_id` indexes if missing
7. ✅ Backup `.env` before changes

### Security Checklist

- [ ] RLS enabled on all 15 critical tables
- [ ] `bionic_application` is NOT a superuser
- [ ] `team_id` indexes exist for performance
- [ ] SSL certificates have correct permissions
- [ ] Application sets `app.current_team_id` on every connection
- [ ] CSP headers present and scored ≥40
- [ ] Web search disabled (unless explicitly needed)

### Maintenance

**Backup Cleanup**:
```bash
sudo eos update moni --cleanup-backups
```
Keeps last 3 `.env.backup.*` files.

**Certificate Validation**:
```bash
sudo eos update moni --validate-certs
```
Run monthly or after infrastructure changes.

**Security Verification**:
```bash
sudo eos update moni --verify-security
```
Run weekly or after application updates.

## References

- **BionicGPT**: https://github.com/bionic-gpt/bionic-gpt
- **PostgreSQL RLS**: https://www.postgresql.org/docs/current/ddl-rowsecurity.html
- **Docker PostgreSQL SSL**: https://www.red-gate.com/simple-talk/databases/running-postgresql-in-docker-with-proper-ssl-and-configuration/
- **Multi-Tenant RLS Best Practices**: https://docs.aws.amazon.com/prescriptive-guidance/latest/saas-multitenant-managed-postgresql/rls.html

## License

See main Eos LICENSE file (AGPL-3.0-or-later + Do No Harm License).

---

**Code Monkey Cybersecurity** (ABN 77 177 673 061)
*Cybersecurity. With humans.*
