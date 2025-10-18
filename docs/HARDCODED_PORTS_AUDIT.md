# Hardcoded Ports Audit

*Last Updated: 2025-10-18*

This document lists all hardcoded port numbers found in the Eos codebase, excluding the centralized ports.go file.

## Summary

The following hardcoded ports were found across the codebase. These should be migrated to use the centralized port definitions in `pkg/shared/ports.go`.

##  HashiCorp Tools Port Standardization (Completed 2025-10-18)

**All HashiCorp tools now use their official default ports:**

| Service | Old Eos Port | New Standard Port | Status |
|---------|--------------|-------------------|---------|
| Vault API | 8200  | 8200 | Already standard |
| Vault Cluster | 8201  | 8201 | Already standard |
| Consul HTTP | 8500  | 8500 | Already standard |
| Consul DNS | 8600  | 8600 | Already standard |
| Consul RPC | 8300  | 8300 | Already standard |
| Consul Serf LAN | 8301  | 8301 | Already standard |
| Consul Serf WAN | 8302  | 8302 | Already standard |
| **Nomad HTTP** | **8243** → **4646** | **4646** |  **Migrated** |
| **Nomad RPC** | **4647**  | **4647** | Already standard |
| **Nomad Serf** | **8377** → **4648** | **4648** |  **Migrated** |

**Changes made:**
- Updated `pkg/shared/ports.go` constants to use HashiCorp defaults
- Fixed incorrect port comments throughout codebase
- Updated environment discovery to prefer `VAULT_ADDR`, `CONSUL_HTTP_ADDR`, `NOMAD_ADDR` env vars
- Updated scripts and examples to reference standard ports
- Verified all Nomad job templates use standard ports
- Verified all Vault HCL templates use standard ports
- Deleted legacy port constants from `pkg/shared/service_addresses.go`

**Benefits:**
- Improved compatibility with HashiCorp documentation
- Reduced confusion for developers familiar with HashiCorp tools
- Simplified codebase by using official SDK defaults
- Better environment variable support following 12-factor app principles

## Hardcoded Ports by Service

### 1. HTTP/HTTPS Services
- **Location**: `pkg/system/security.go`
  - Port 80 (HTTP): `{Action: "allow", Protocol: "tcp", Port: "80", Source: "any", Comment: "HTTP"}`
  - Port 443 (HTTPS): `{Action: "allow", Protocol: "tcp", Port: "443", Source: "any", Comment: "HTTPS"}`

- **Location**: `pkg/deploy/traefik.go`
  - Port 80: `httpPort = "80"`
  - Port 443: `httpsPort = "443"`

- **Location**: `pkg/terraform/k3s_caddy_nginx.go`
  - Port 80: `port = "80"`
  - Port 443: `port = "443"`

### 2. Database Services
- **Location**: `pkg/eos_postgres/postgres_test.go`, `postgres_fuzz_test.go`
  - Port 5432 (PostgreSQL): Multiple occurrences in test DSN strings
  - Example: `"postgres://user:pass@localhost:5432/dbname?sslmode=disable"`

- **Location**: `cmd/create/postgres.go`
  - Port 5432: Default in flag definition: `databaseVaultPostgresCmd.Flags().Int("port", 5432, "Database port")`

### 3. Vault Services
-  **MIGRATED**: All Vault references now use port 8200 (HashiCorp standard)

- **Location**: `pkg/shared/vault_server.go`
  - Port 8200: `VaultDefaultPort` (HashiCorp standard) 

- **Location**: `pkg/vault/constants.go`
  - Port 8200: `DefaultAddress = "https://127.0.0.1:8200"` 

- **Location**: Multiple vault-related files
  - Port 8200: Used consistently across test files and configurations 

### 4. Consul Services
-  **MIGRATED**: All Consul references now use HashiCorp standard ports

- **Location**: `pkg/terraform/consul_templates.go`
  - Port 8500: Consul HTTP API (HashiCorp standard) 
  - Port 8600: Consul DNS (HashiCorp standard) 
  - Port 8300: Consul server RPC (HashiCorp standard) 
  - Port 8301: Consul Serf LAN (HashiCorp standard) 
  - Port 8302: Consul Serf WAN (HashiCorp standard) 

- **Location**: `cmd/create/consul_orchestrated.go`
  - Port 8200: Vault integration default 

### 5. Monitoring Services
- **Location**: `pkg/wazuh_mssp/configure.go`
  - Port 9090: Prometheus metrics `targets: ['localhost:9090']`

- **Location**: `pkg/container/zabbix.go`
  - Port 10051: `zabbixServerPort := "10051"`
  - Port 10050: `zabbixAgentPort := "10050"`

### 6. Container/Kubernetes Services
- **Location**: `pkg/container/k3s_test.go`
  - Port 6443: Kubernetes API server

- **Location**: `pkg/terraform/templates.go`, `vault_templates.go`
  - Port 6443: Kubernetes API
  - Port 10250: Kubelet
  - Port 8472: Flannel VXLAN

### 7. Application Services
- **Location**: `cmd/create/grafana.go`
  - Port 3000: Default Grafana port

- **Location**: `cmd/create/ollama.go`
  - Port 3000: Ollama Web UI default

- **Location**: `cmd/create/guacamole.go`
  - Port 8080: Default Guacamole port

- **Location**: `cmd/create/hecate_api.go`
  - Port 8080: Hecate API default

- **Location**: `cmd/create/headscale.go`
  - Port 80, 443, 41641: Headscale firewall ports

- **Location**: `cmd/create/zabbix.go`
  - Port 8080: Zabbix web interface default
  - Port 8443: Zabbix SSL interface

### 8. Development/Test Services
- **Location**: `pkg/container/jenkins_test.go`
  - Port 8080: Jenkins UI
  - Port 50000: Jenkins agent

- **Location**: `pkg/build/orchestrator.go`
  - Port 8080: Build service default

### 9. Nomad Services
-  **MIGRATED**: All Nomad references now use HashiCorp standard ports

- **Location**: `pkg/nomad/deploy.go`, `pkg/shared/ports.go`
  - Port 4646: Nomad HTTP API (HashiCorp standard) 
  - Port 4647: Nomad RPC (HashiCorp standard) 
  - Port 4648: Nomad Serf (HashiCorp standard) 

- **Location**: `pkg/orchestrator/terraform/provider.go`
  - Port 4646: Nomad HTTP default 

### 10. SSH Services
- **Location**: Multiple terraform files
  - Port 22: SSH access in firewall rules

### 11. Docker Compose Files
- **Location**: `assets/docker/penpot-docker-compose.yml`
  - Port 5432: PostgreSQL
  - Port 6379: Redis
  - Port 8239: Penpot main interface
  - Port 6060: Penpot backend API
  - Port 6061: Penpot exporter

## Recommendations

1. **Immediate Action Required**:
   - Move all hardcoded ports to `pkg/shared/ports.go`
   - Update all references to use the centralized port constants
   - This is especially critical for frequently used ports like 8080, 3000, 5432

2. **Test Files**:
   - While test files often need specific port examples, consider using constants from ports.go where appropriate
   - For DSN examples, consider using template strings with port constants

3. **Configuration Files**:
   - Docker Compose and other configuration files should reference environment variables that are set from the centralized port definitions

4. **Command Flags**:
   - Default values in command flags should reference the centralized constants rather than hardcoding values

5. **Security Considerations**:
   - Having centralized port management makes it easier to audit and change ports for security purposes
   - Reduces the risk of port conflicts when multiple services are deployed

## Migration Priority

1. ** Completed** (HashiCorp Tools - 2025-10-18):
   -  Vault (8200) - Now using HashiCorp standard
   -  Consul (8500, 8600, 8300-8302) - Now using HashiCorp standards
   -  Nomad (4646, 4647, 4648) - Migrated from 8243/8377 to HashiCorp standards

2. **High Priority Remaining** (Production Services):
   - PostgreSQL (5432)
   - HTTP/HTTPS (80, 443)

3. **Medium Priority** (Application Services):
   - Grafana (3000)
   - Zabbix (10051, 10050, 8080)
   - Kubernetes/K3s (6443, 10250)

4. **Low Priority** (Development/Test):
   - Jenkins (8080, 50000)
   - Test DSN strings
   - Example configurations