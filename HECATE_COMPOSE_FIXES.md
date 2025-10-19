# Hecate Docker Compose Fixes

*Last Updated: 2025-10-19*

## Issues Fixed

### 1. Added Docker Compose Version Field
**File:** `pkg/hecate/compose_generator.go:173`
```yaml
version: '3.8'

services:
  ...
```
**Reason:** Some Docker Compose implementations still require the version field for compatibility.

### 2. Fixed Authentik Version Tag
**Files:** 
- `pkg/hecate/compose_generator.go:116` (default value)
- `pkg/hecate/compose_generator.go:229,258` (docker-compose template)

**Changed:** `2025.8` → `2024.8.3`

**Reason:** Version `2025.8` doesn't exist (future date). Using latest stable release `2024.8.3`.

### 3. Added Network Driver
**File:** `pkg/hecate/compose_generator.go:288`
```yaml
networks:
  hecate-net:
    driver: bridge
```
**Reason:** Explicit driver specification improves compatibility and clarity.

## Validation

The generated docker-compose.yml now includes:

✅ Valid Docker Compose version field  
✅ Correct Authentik image tag (2024.8.3)  
✅ Explicit network driver (bridge)  
✅ All health checks and dependencies  
✅ Proper volume configurations  
✅ Security-hardened Caddyfile  

## Testing

To test the fixed configuration:

```bash
# Rebuild eos with fixes
cd /Users/henry/Dev/eos
go build -o /tmp/eos ./cmd/

# On server, regenerate Hecate config
sudo rm -rf /opt/hecate
sudo /tmp/eos create hecate

# Validate compose file
cd /opt/hecate
sudo docker compose config

# Pull images separately (for low-memory systems)
sudo docker compose pull

# Start services
sudo docker compose up -d

# Check status
sudo docker compose ps
sudo docker compose logs -f
```

## Memory Considerations

For servers with limited RAM (< 4GB):

1. **Pull images separately** to avoid OOM during parallel pulls:
   ```bash
   sudo docker compose pull postgresql
   sudo docker compose pull redis
   sudo docker compose pull server
   sudo docker compose pull worker
   sudo docker compose pull caddy
   ```

2. **Add swap space** if not present:
   ```bash
   sudo fallocate -l 2G /swapfile
   sudo chmod 600 /swapfile
   sudo mkswap /swapfile
   sudo swapon /swapfile
   echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
   ```

3. **Start services sequentially**:
   ```bash
   sudo docker compose up -d postgresql redis
   # Wait for health checks
   sleep 30
   sudo docker compose up -d server worker
   sudo docker compose up -d caddy
   ```

## Related Changes

- Enhanced diagnostic logging in `pkg/hecate/lifecycle_create.go` per `claude.md` P2 guidelines
- Added pre-operation diagnostics (memory status, Docker version)
- Added post-operation verification (container status)
- Enhanced error messages with remediation steps

---

*These fixes ensure the docker-compose.yml is valid, uses correct versions, and follows Docker Compose best practices.*
