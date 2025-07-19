# SaltStack Infrastructure Scaling Guide

## Overview

This guide provides a comprehensive framework for deploying and scaling infrastructure in resource-constrained environments. It outlines optimal service deployment patterns as you scale from a single node to multiple nodes, with a focus on balancing security, reliability, and functionality at each scaling point.

## Core Infrastructure Stack

### Base Requirements (All Deployments)
- **Operating System**: Ubuntu Server 24.04 LTS
- **Configuration Management**: SaltStack
- **Infrastructure as Code**: Terraform
- **Container Orchestration**: Nomad

### Essential Services (Minimum Viable Infrastructure)
- **Reverse Proxy**: Caddy or Nginx
- **Authentication**: Authentik
- **Basic Monitoring**: Grafana
- **Lightweight Web Application**: Your choice

## Scaling Philosophy

The key principle is **progressive enhancement**: start with the absolute minimum viable infrastructure and add capabilities as resources become available. Each scaling tier introduces new capabilities while maintaining the security and reliability achievements of previous tiers.

**Important**: Frontend/edge nodes should remain lightweight and focused solely on traffic routing, authentication, and security. All application logic, data storage, and management services belong on backend nodes.

## Node Scaling Tiers

### Tier 1: Single Node (Survival Mode)

**Resource Requirements**: 4 vCPUs, 8GB RAM, 100GB SSD

**Service Deployment**:
```yaml
single_node:
  services:
    required:
      - Ubuntu Server
      - Docker/Containerd
      - Nomad (server + client)
      - Caddy (with automatic HTTPS)
      - Authentik (minimal config)
      - Grafana (local metrics only)
      - SaltStack Minion (masterless mode)
      - Tailscale (for remote access)
      - Terraform (local state)
    
    configuration:
      - All services in containers via Nomad
      - Local file-based secrets (encrypted)
      - Caddy handles TLS termination
      - SQLite databases for stateful services
      - Local backup to external USB/NFS
```

**Accepted Risks**:
- No redundancy or high availability
- Secrets stored in encrypted files (not Vault)
- Manual disaster recovery process
- No real-time monitoring/alerting
- Single point of failure

**Backup Strategy**:
- Daily encrypted tarballs to external storage
- Database dumps before backup
- Configuration files in Git repository

### Tier 2: Two Nodes (Security/Reliability Fork)

**Resource Requirements**: 6 vCPUs, 12GB RAM, 200GB SSD per node

At two nodes, you must choose between prioritizing security or reliability:

#### Option A: Security-Focused Deployment
```yaml
security_focused:
  node1_dmz:
    role: "Edge/DMZ"
    services:
      - Nginx (reverse proxy)
      - Boundary (zero-trust access)
      - Tailscale
      - SaltStack Minion
      - Authentik (auth gateway only)
      - Nomad (client only - for edge services)
      - Terraform (read-only state access)
    
    notes:
      - "NO Wazuh Agent - requires Wazuh Manager on backend first"
      - "Authentik runs in gateway mode only"
      - "Minimal local storage - all data on backend"
    
  node2_backend:
    role: "Secure Backend"
    services:
      - Nomad (server + client)
      - Vault (secrets management)
      - Grafana
      - SaltStack Master
      - Local backup service
      - Application containers
      - Database services
      - Wazuh Manager (if compliance needed)
      - Terraform (state backend)
```

#### Option B: Reliability-Focused Deployment
```yaml
reliability_focused:
  node1_primary:
    role: "Primary Services"
    services:
      - Caddy (reverse proxy)
      - Tailscale
      - SaltStack Minion
      - Authentik (auth gateway)
      - Nomad (client only)
      - Terraform (read-only)
  
  node2_secondary:
    role: "Backend/Apps"
    services:
      - Nomad (server + client)
      - Grafana
      - Application containers
      - Backup services
      - SaltStack Master
      - Database services
      - Terraform (state backend)
```

**Key Decisions at 2 Nodes**:
- **Frontend Isolation**: Keep edge nodes stateless and minimal
- **Wazuh Deployment**: Manager MUST be on backend before agents can be deployed
- **Vault vs Backups**: If handling sensitive data → Vault first. Otherwise → Backups first
- **Salt Master**: Always on backend node
- **Networking**: Keep Tailscale for now (simpler than Consul at this scale)

### Tier 3: Three Nodes (Balanced Triad)

**Resource Requirements**: 8 vCPUs, 16GB RAM, 300GB SSD per node

```yaml
three_node_deployment:
  node1_edge:
    role: "Edge Services"
    services:
      - Nginx (primary reverse proxy)
      - Caddy (backup reverse proxy)
      - Boundary (zero-trust access)
      - SaltStack Minion
      - Tailscale
      - Authentik (auth gateway mode)
      - Nomad (client only)
      - Terraform (read-only access)
    
    conditional_services:
      - Wazuh Agent (ONLY if node3 has Wazuh Manager running)
    
  node2_apps:
    role: "Application Services"
    services:
      - Nomad (server)
      - Vault (primary secrets)
      - SaltStack Master
      - Consul Server (if migrating from Tailscale)
      - Primary application containers
      - Database services
      - Terraform (state backend)
    
  node3_data:
    role: "Data Services"
    services:
      - Grafana
      - Prometheus
      - Backup services (for all nodes)
      - Nomad (server - part of 3-node cluster)
      - Consul Server (if using)
      - Secondary application containers
      - Wazuh Manager (enables agents on other nodes)
      - Log aggregation services
```

**Key Decisions at 3 Nodes**:
- **Edge Remains Minimal**: Node 1 only handles traffic routing and auth
- **Wazuh Deployment Order**: Manager on Node 3 first, then agents can be deployed
- **Vault Placement**: Keep with apps (Node 2), NOT on backup node
- **Consul vs Tailscale**: 
  - Stay with Tailscale if you only need connectivity
  - Switch to Consul if you need service discovery/health checks
- **Monitoring Priority**: Grafana + Prometheus before Jenkins
- **Backup Strategy**: Node 3 backs up Nodes 1 & 2 daily

### Tier 4+: Four or More Nodes (Specialized Infrastructure)

**Resource Requirements**: 12 vCPUs, 32GB RAM, 500GB SSD per node

```yaml
specialized_deployment:
  node1_edge:
    role: "Edge/Security"
    services:
      - Nginx cluster
      - Boundary cluster
      - WAF capabilities
      - DDoS protection
      - Tailscale/Consul agent
      - SaltStack Minion
      - Authentik (gateway mode)
      - Nomad (client only)
      - Terraform (read-only)
      - Wazuh Agent (after manager deployed)
  
  node2_control:
    role: "Control Plane"
    services:
      - Vault (HA mode)
      - SaltStack Master (HA)
      - Consul Server
      - Terraform (primary state backend)
      - Nomad (server - control)
  
  node3_apps:
    role: "Application Tier"
    services:
      - Nomad (server + client)
      - Application containers
      - Database services
      - API services
      - Cache services
  
  node4_data:
    role: "Data/Monitoring"
    services:
      - Prometheus
      - Grafana
      - Elasticsearch/OpenSearch
      - Wazuh Manager (enables all agents)
      - Backup orchestration
      - Log aggregation
  
  node5_cicd:
    role: "CI/CD (if added)"
    services:
      - Jenkins/GitLab
      - Container registry
      - Build agents
      - Artifact storage
```

## Service Dependency Matrix

### Critical Dependencies
| Service | Requires | Location |
|---------|----------|----------|
| Wazuh Agent | Wazuh Manager must be running | Edge nodes AFTER backend |
| Authentik (full) | Database backend | Backend only |
| Authentik (gateway) | Connection to backend Authentik | Edge nodes |
| Vault | Secure backend storage | Backend only |
| Nomad Server | Quorum (3+ for HA) | Backend nodes |
| Terraform State | Secure backend | Backend only |

### Service Placement Rules

**ALWAYS on Edge/Frontend**:
- Reverse Proxy (Nginx/Caddy)
- Boundary (if used)
- VPN/Tailscale endpoint
- WAF/Security filters
- Salt Minion
- Nomad Client (for edge workloads only)

**NEVER on Edge/Frontend**:
- Databases
- Vault
- Salt Master
- Monitoring data stores
- Backup services
- Application containers (except edge-specific)
- Terraform state backend

## Wazuh Deployment Strategy

### Important: Wazuh has strict deployment order requirements

1. **No Wazuh at 1 Node**: Skip entirely unless compliance requires it
2. **Wazuh at 2+ Nodes**:
   - FIRST: Deploy Wazuh Manager on backend/data node
   - WAIT: Ensure Manager is fully operational
   - THEN: Deploy Wazuh Agents on other nodes
   - NEVER: Deploy agents without a manager

### Wazuh Architecture
```
Backend Node (Wazuh Manager)
    ↓ 
    ├── Edge Node (Wazuh Agent)
    ├── App Node (Wazuh Agent)
    └── Other Nodes (Wazuh Agents)
```

## Service Priority Matrix

### Critical Path Services (Deploy First)
1. **Networking**: Tailscale → Consul (at scale)
2. **Security**: Basic Auth → Authentik → Vault → Boundary
3. **Observability**: Logs → Metrics → Traces
4. **Data Protection**: Local Backup → Remote Backup → Replication

### Enhancement Services (Deploy as Resources Allow)
1. **Monitoring**: Grafana → Prometheus → Wazuh
2. **Automation**: Salt Master → Jenkins/GitLab CI
3. **Service Mesh**: Consul Connect
4. **Advanced Security**: Wazuh XDR, Falco

## Decision Framework

### When to Add Services

| Service | Add When | Where |
|---------|----------|--------|
| Vault | Handling sensitive data OR 2+ nodes | Backend only |
| Consul | Need service discovery OR 3+ nodes | Backend (servers), All (agents) |
| Prometheus | Need historical metrics OR 3+ nodes | Data node |
| Jenkins | Have dedicated ops team OR 4+ nodes | Dedicated CI/CD node |
| Wazuh Manager | Compliance requirements OR 3+ nodes | Data/monitoring node |
| Wazuh Agents | After Manager is deployed | All nodes |
| Boundary | External user access OR zero-trust required | Edge nodes only |

### Resource Allocation Guidelines

**Edge Node Allocation**:
- OS + Base Services: 30%
- Reverse Proxy: 20%
- Auth Gateway: 20%
- Security Services: 20%
- Overhead/Burst: 10%

**Backend Node Allocation**:
- OS + Base Services: 20%
- Application Workloads: 50%
- Monitoring/Security: 20%
- Overhead/Burst: 10%

**Memory Allocation**:
- Edge Nodes: 4-8GB total
- Backend Nodes: 8-32GB depending on workload
- Database Nodes: 50% for database, 50% for OS/cache

**Storage Allocation**:
- Edge Nodes: 50GB (logs and cache only)
- Backend Nodes: 200GB+ (applications and data)
- Monitoring Nodes: 500GB+ (metrics retention)

## Networking Architecture

### Single Node
```
Internet → Firewall → Caddy → Applications
                        ↓
                   Tailscale (Management)
```

### Multi-Node
```
Internet → Firewall → Edge Node(s) → Backend Nodes
                           ↓              ↓
                      Management Network (Tailscale/Consul)
                           ↓              ↓
                      Data/Backup ← → Control Plane
```

### Network Segmentation
```
Public Network:     Internet ↔ Edge Nodes only
Management Network: All nodes (Tailscale/VPN)
Data Network:       Backend nodes only
Backup Network:     Backend ↔ Backup storage
```

## Security Considerations

### Defense in Depth Layers
1. **Perimeter**: Firewall, DDoS protection (Edge only)
2. **Edge**: Reverse proxy, WAF, rate limiting (Edge only)
3. **Access**: Boundary, VPN, zero-trust (Edge only)
4. **Application**: Authentik, RBAC, API security (Backend)
5. **Data**: Vault, encryption at rest/transit (Backend)
6. **Monitoring**: Wazuh, audit logs, SIEM (Backend manager, agents everywhere)

### Secret Management Evolution
1. **1 Node**: Encrypted files + environment variables
2. **2 Nodes**: Vault on backend, edge accesses via API
3. **3+ Nodes**: Vault with Consul backend, auto-unseal

## Backup and Disaster Recovery

### Backup Strategy by Tier

**Tier 1 (1 Node)**:
- Manual daily backups to external storage
- Git for configuration
- Document recovery procedures

**Tier 2 (2 Nodes)**:
- Backend backs up both nodes
- Edge node remains stateless (nothing to backup)
- 7-day retention

**Tier 3 (3 Nodes)**:
- Dedicated backup on data node
- Automated hourly snapshots
- 30-day retention
- Off-site replication

**Tier 4+ (4+ Nodes)**:
- Backup orchestration platform
- Continuous replication
- Point-in-time recovery
- Automated DR testing

### Recovery Time Objectives (RTO)
- **Edge Nodes**: 15 minutes (stateless, quick redeploy)
- **Backend Tier 1**: 4-8 hours (manual)
- **Backend Tier 2**: 2-4 hours (semi-automated)
- **Backend Tier 3**: 1 hour (automated)
- **Backend Tier 4+**: 15 minutes (HA failover)

## Configuration Management

### SaltStack Deployment Patterns

**Edge Nodes**: 
- Always Salt Minion only
- Pull states from Master
- No local state storage

**Backend Nodes**:
- 1 Node: Masterless minion
- 2+ Nodes: Dedicated Master on backend
- 3+ Nodes: Consider Master HA

### Example Salt State Structure
```
/srv/salt/
├── top.sls
├── roles/
│   ├── edge/
│   │   ├── nginx.sls
│   │   ├── boundary.sls
│   │   └── authentik-gateway.sls
│   ├── backend/
│   │   ├── vault.sls
│   │   ├── nomad-server.sls
│   │   └── databases.sls
│   └── monitoring/
│       ├── wazuh-manager.sls
│       └── wazuh-agent.sls
└── orchestration/
    ├── deploy/
    └── backup/
```

## Monitoring and Observability

### Metrics Collection by Tier

**Tier 1**: Host metrics only (CPU, RAM, Disk)
**Tier 2**: + Container metrics, basic alerting
**Tier 3**: + Application metrics, Prometheus
**Tier 4+**: + Distributed tracing, APM

### Key Metrics to Monitor

**Edge Nodes**:
- Request rate, Error rate, Latency
- TLS handshakes, Connection count
- WAF blocks, Auth failures

**Backend Nodes**:
- Application performance
- Database queries
- Queue depths
- Resource utilization

## Common Pitfalls to Avoid

1. **Stateful edge nodes**: Keep edge nodes stateless and replaceable
2. **Wrong service placement**: Don't put databases or state on edge
3. **Deploying Wazuh agents before manager**: Always deploy manager first
4. **Over-provisioning edge**: Edge nodes should be lightweight
5. **Under-provisioning backend**: Backend needs resources for growth
6. **Mixing concerns**: Keep edge focused on routing/security only

## Migration Paths

### Tailscale → Consul
1. Install Consul servers on backend first
2. Deploy Consul agents to all nodes
3. Register backend services in Consul
4. Update service discovery gradually
5. Maintain Tailscale for management access

### Single Node → Multi-Node
1. Backup everything first
2. Deploy backend node
3. Move stateful services to backend
4. Convert existing node to edge role
5. Update DNS to point to edge node

## Automation Templates

### Terraform Module Structure
```
modules/
├── edge-node/
│   ├── nginx.tf
│   ├── boundary.tf
│   └── security.tf
├── backend-node/
│   ├── nomad.tf
│   ├── vault.tf
│   └── apps.tf
├── data-node/
│   ├── monitoring.tf
│   └── backup.tf
└── networking/
    ├── tailscale.tf
    └── firewall.tf
```

### Nomad Job Priorities
1. **System** (90-100): Core infrastructure
2. **Service** (50-89): Business applications  
3. **Batch** (10-49): Background jobs
4. **Best Effort** (0-9): Non-critical tasks

## Performance Tuning

### Edge Node Limits
- **Nginx**: 512MB RAM, 0.5 CPU
- **Boundary**: 1GB RAM, 1 CPU
- **Authentik Gateway**: 512MB RAM, 0.5 CPU
- **Total Edge Node**: 4GB RAM, 2 CPU minimum

### Backend Service Limits
- **Vault**: 2GB RAM, 2 CPU
- **Consul**: 2GB RAM, 2 CPU  
- **Nomad Server**: 2GB RAM, 2 CPU
- **Grafana**: 1GB RAM, 1 CPU
- **Prometheus**: 4GB RAM, 2 CPU
- **Wazuh Manager**: 4GB RAM, 4 CPU

### Optimization Tips
1. Use SSD for backend databases
2. Separate network interfaces for public/private traffic
3. Enable compression on edge proxies
4. Implement caching at edge layer
5. Regular maintenance windows for updates

## Conclusion

This scaling guide emphasizes the critical importance of proper service placement. Edge nodes must remain lightweight and focused solely on traffic handling and security. All stateful services, management tools, and application logic belong on backend nodes.

Remember: 
- **Edge nodes are disposable** - they should be able to be destroyed and rebuilt quickly
- **Backend nodes are precious** - they hold your data and state
- **Deploy dependencies first** - especially Wazuh Manager before agents
- **Start simple** - complexity can always be added later

Focus on getting the service placement right at each tier before moving to the next.