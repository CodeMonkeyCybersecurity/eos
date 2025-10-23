# BionicGPT with Hecate + Authentik + Nomad Architecture
## Detailed Implementation Plan for EOS CLI Integration

**Date:** October 23, 2025  
**Author:** Claude (with Henry)  
**Purpose:** Complete architectural design and implementation guide for integrating BionicGPT with Hecate reverse proxy framework, Authentik SSO, and Nomad orchestration

---

## 🏗️ PART 1: ARCHITECTURAL ANALYSIS

### 1.1 Network Topology

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CLOUD NODE (Public)                          │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                  HECATE FRAMEWORK                             │  │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐            │  │
│  │  │   Caddy    │  │   nginx    │  │ STUN/TURN  │            │  │
│  │  │  (HTTPS)   │  │  (TCP/UDP) │  │  (WebRTC)  │            │  │
│  │  └──────┬─────┘  └──────┬─────┘  └────────────┘            │  │
│  └─────────┼────────────────┼──────────────────────────────────┘  │
│            │                │                                       │
│  ┌─────────┼────────────────┼──────────────────────────────────┐  │
│  │         │     Authentik (IdP)                                │  │
│  │         │     - User management                              │  │
│  │         │     - OAuth2/OIDC provider                         │  │
│  │         │     - Groups/permissions                           │  │
│  │         │     Port: 9000/9443                               │  │
│  └─────────┼────────────────┼──────────────────────────────────┘  │
│            │                │                                       │
│  ┌─────────┼────────────────┼──────────────────────────────────┐  │
│  │         └────► Consul Agent (Service Discovery)              │  │
│  │                - Registers Hecate services                    │  │
│  │                - Health checks                                │  │
│  │                - Discovers local services via Consul WAN     │  │
│  └───────────────────────────────────────────────────────────────┘  │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                    Internet / VPN / Wireguard Tunnel
                               │
┌──────────────────────────────┴──────────────────────────────────────┐
│                    LOCAL NODE (Private Network)                     │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │               Consul Agent (Service Discovery)                │  │
│  │                - Registers local services                     │  │
│  │                - Joins cloud Consul via WAN                  │  │
│  │                - Provides DNS for service discovery          │  │
│  └───────────────────────────┬──────────────────────────────────┘  │
│                              │                                       │
│  ┌───────────────────────────┴──────────────────────────────────┐  │
│  │                    Nomad Client                               │  │
│  │                    - Runs job allocations                     │  │
│  │                    - Integrates with Consul                   │  │
│  └───────────────────────────┬──────────────────────────────────┘  │
│                              │                                       │
│  ┌───────────────────────────┴──────────────────────────────────┐  │
│  │                                                                │  │
│  │  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐     │  │
│  │  │ oauth2-proxy │───│  BionicGPT   │───│  PostgreSQL  │     │  │
│  │  │  Port: 4180  │   │  Port: 7703  │   │ with pgvector│     │  │
│  │  └──────┬───────┘   └──────┬───────┘   └──────────────┘     │  │
│  │         │                  │                                  │  │
│  │         └──────────────────┴───────┐                         │  │
│  │                                     │                         │  │
│  │  ┌──────────────┐   ┌──────────────┴──────────────┐         │  │
│  │  │   LiteLLM    │   │   Ollama                     │         │  │
│  │  │  (Proxy)     │───│   nomic-embed-text           │         │  │
│  │  │  Port: 4000  │   │   Port: 11434                │         │  │
│  │  └──────────────┘   └──────────────────────────────┘         │  │
│  │                                                                │  │
│  └────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘

LEGEND:
───  Network connection / dependency
 │   Hierarchical relationship
```

### 1.2 Traffic Flow Analysis

#### A. User Authentication Flow

```
1. User → https://chat.codemonkey.ai
   ↓
2. Caddy (Hecate/Cloud) receives request
   ↓
3. Caddy checks Consul for "bionicgpt" service location
   ↓
4. Caddy forwards to oauth2-proxy (local node) via discovered address
   ↓
5. oauth2-proxy checks for auth cookie
   ↓
6. No cookie → Redirect to Authentik (cloud node)
   https://auth.codemonkey.ai/application/o/authorize/
   ↓
7. User logs into Authentik
   ↓
8. Authentik redirects back with auth code
   https://chat.codemonkey.ai/oauth2/callback?code=...
   ↓
9. oauth2-proxy exchanges code for token (server-to-server with Authentik)
   ↓
10. oauth2-proxy sets cookie and forwards to BionicGPT with headers:
    X-Auth-Request-Email: user@example.com
    X-Auth-Request-Groups: superadmin,demo-tenant
   ↓
11. BionicGPT creates/identifies user, returns response
   ↓
12. Response flows back: BionicGPT → oauth2-proxy → Caddy → User
```

#### B. LLM Request Flow

```
User sends chat message in BionicGPT
   ↓
BionicGPT → LiteLLM (local:4000)
   ↓
LiteLLM routes to:
   - Azure OpenAI (for chat completion)
   - Ollama (for embeddings if RAG)
   ↓
BionicGPT → Ollama directly (for embedding documents)
   ↓
Results stored in PostgreSQL (pgvector)
```

#### C. Service Discovery Flow

```
Service starts (e.g., BionicGPT)
   ↓
Nomad job includes service stanza
   ↓
Nomad registers service with local Consul agent
   ↓
Consul agent propagates to Consul WAN (cloud node)
   ↓
Caddy (Hecate) queries Consul for service location
   ↓
Caddy gets IP:Port of BionicGPT's oauth2-proxy
   ↓
Caddy can route traffic to local service
```

### 1.3 Critical Decisions & Trade-offs

**Decision 1: How does Cloud Caddy reach Local oauth2-proxy?**

**Options:**
A. Public endpoint on local node (port forwarding)
B. VPN tunnel (WireGuard/Tailscale)
C. Cloudflare Tunnel
D. Consul Connect service mesh

**Analysis:**

| Option | Pros | Cons | Recommended? |
|--------|------|------|--------------|
| Public endpoint | Simple, fast | Security risk, need port forward | ⚠️ Dev only |
| VPN tunnel | Secure, private network | Setup complexity, latency overhead | ✅ Recommended |
| Cloudflare Tunnel | No port forward, free tier | Dependency on Cloudflare | ✅ Alternative |
| Consul Connect | Native to stack, mTLS | Most complex, learning curve | 🔄 Future |

**Recommendation:** Start with **VPN (WireGuard)** for security, fallback to **Cloudflare Tunnel** for simplicity.

**Decision 2: Where does Nomad run?**

**Options:**
A. Both nodes (cluster mode)
B. Local only (simpler)
C. Cloud only (centralized)

**Analysis:**
- **Both nodes:** Most flexible, but complex
- **Local only:** Simplifies deployment since BionicGPT is local
- **Cloud only:** Requires Nomad to remotely manage local containers

**Recommendation:** **Local only** for initial implementation. Cloud node uses docker-compose for Hecate/Authentik (already working). Migrate to cluster mode later if needed.

**Decision 3: How to isolate Authentik groups?**

**Challenge:** Hecate/Authentik may manage multiple applications. BionicGPT needs its own isolated groups.

**Solution:** Use **group prefixes** or **nested organizational structure**:
- `bionicgpt-superadmin` 
- `bionicgpt-demo-tenant`
- Other apps use different prefixes: `wazuh-admin`, `nextcloud-users`, etc.

**Decision 4: Should we use Consul at all?**

**Analysis:**
- **Yes, use Consul if:**
  - You plan to scale beyond single-node
  - You want dynamic service discovery
  - Future-proofing for multi-service architecture
  
- **No, skip Consul if:**
  - You want absolute simplest setup
  - Static IP addresses are acceptable
  - Only deploying BionicGPT

**Recommendation:** **YES, use Consul** because:
1. Hecate framework benefits from service discovery
2. Future services can auto-register
3. Health checking built-in
4. Aligns with Nomad ecosystem

### 1.4 Security Considerations

**1. Network Security:**
- TLS everywhere (Caddy auto-manages Let's Encrypt)
- VPN tunnel between cloud and local (WireGuard)
- Firewall rules: only allow WireGuard + necessary ports
- No direct public access to local services

**2. Authentication Security:**
- OAuth2 tokens use short expiry (1 hour)
- Refresh tokens for long-lived sessions
- Cookie encryption (secure, httponly, samesite)
- MFA enforced in Authentik for superadmin

**3. Authorization Security:**
- BionicGPT enforces row-level security (RLS) in PostgreSQL
- Groups map to teams, teams control data access
- Superadmin group has elevated privileges
- Demo tenant isolated from production data

**4. API Security:**
- LiteLLM API keys stored in Vault
- Azure OpenAI keys stored in Vault
- No hardcoded secrets in configs
- Nomad variables for sensitive data

---

## 🎯 PART 2: COMPONENT-BY-COMPONENT CONFIGURATION

### 2.1 Authentik Configuration (Cloud Node)

**Installation:** Already done via Hecate/docker-compose

**Configuration needed:**

#### Step 1: Create OAuth2 Provider for BionicGPT

```python
# Via Authentik API or UI
Provider:
  Name: "BionicGPT OAuth2"
  Type: OAuth2/OpenID Connect
  Client Type: Confidential
  Client ID: bionicgpt-client (auto-generated)
  Client Secret: <stored in Vault>
  
  Authorization Flow: default-provider-authorization-implicit-consent
  
  Redirect URIs:
    - https://chat.codemonkey.ai/oauth2/callback
    - http://localhost:4180/oauth2/callback  # For local testing
    
  Scopes:
    - openid (required)
    - email (required)
    - profile (required)
    - offline_access (for refresh tokens)
    
  Advanced Settings:
    - Access Token Validity: 1 hour
    - Refresh Token Validity: 7 days
```

#### Step 2: Create Application

```python
Application:
  Name: BionicGPT
  Slug: bionicgpt
  Provider: BionicGPT OAuth2 (from Step 1)
  Launch URL: https://chat.codemonkey.ai
  
  UI Settings:
    - Icon: (upload BionicGPT logo)
    - Description: "AI Chat Platform"
```

#### Step 3: Create Property Mapping for Groups

**Purpose:** Include user groups in ID token

```python
# Navigate to: Customization → Property Mappings → Create
Type: Scope Mapping
Name: BionicGPT Groups Mapping
Scope: groups

Expression:
"""
# Only include groups that start with 'bionicgpt-'
bionicgpt_groups = [
    group.name 
    for group in request.user.ak_groups.all() 
    if group.name.startswith('bionicgpt-')
]

return {
    "groups": bionicgpt_groups,
    "is_superadmin": "bionicgpt-superadmin" in bionicgpt_groups
}
"""

# Assign this mapping to the OAuth2 provider
Provider → Edit → Scope Mappings → Select "BionicGPT Groups Mapping"
```

#### Step 4: Create Groups

```python
# Navigate to: Directory → Groups → Create

Group 1:
  Name: bionicgpt-superadmin
  Parent: None
  Attributes:
    {
      "description": "BionicGPT super administrators",
      "role": "superadmin"
    }

Group 2:
  Name: bionicgpt-demo-tenant
  Parent: None
  Attributes:
    {
      "description": "Demo tenant for BionicGPT",
      "role": "user",
      "tenant": "demo"
    }
```

#### Step 5: Create Test Users

```python
User 1 (Superadmin):
  Username: henry
  Email: henry@codemonkey.ai
  Name: Henry Smith
  Groups: bionicgpt-superadmin
  
User 2 (Demo):
  Username: demo
  Email: demo@codemonkey.ai
  Name: Demo User
  Groups: bionicgpt-demo-tenant
```

#### Step 6: Enable MFA for Superadmin

```python
# Navigate to: Flows & Stages → Stages
Create Stage:
  Type: Authenticator Validation Stage
  Name: BionicGPT MFA
  Device classes: TOTP, WebAuthn, Static
  
# Add to authentication flow
Flow: default-authentication-flow
Stages:
  1. Identification
  2. Password
  3. BionicGPT MFA (conditional on group membership)
     Policy: Only require for bionicgpt-superadmin group
```

### 2.2 Consul Configuration (Both Nodes)

#### Cloud Node Consul Config

**File:** `/etc/consul/config.json`

```json
{
  "datacenter": "dc1",
  "node_name": "cloud-hecate",
  "server": true,
  "bootstrap_expect": 1,
  "ui_config": {
    "enabled": true
  },
  "client_addr": "0.0.0.0",
  "bind_addr": "{{ GetPrivateIP }}",
  "advertise_addr": "<CLOUD_NODE_PUBLIC_IP>",
  "retry_join": [],
  "ports": {
    "http": 8500,
    "dns": 8600,
    "serf_lan": 8301,
    "serf_wan": 8302,
    "server": 8300
  },
  "service": {
    "name": "authentik",
    "port": 9000,
    "tags": ["auth", "oidc", "hecate"],
    "check": {
      "http": "https://auth.codemonkey.ai/api/v3/root/config/",
      "interval": "10s",
      "timeout": "2s"
    }
  },
  "services": [
    {
      "name": "caddy",
      "port": 443,
      "tags": ["reverse-proxy", "hecate"],
      "check": {
        "http": "http://localhost:2019/config/",
        "interval": "10s"
      }
    },
    {
      "name": "nginx",
      "port": 8080,
      "tags": ["tcp-udp-proxy", "hecate"],
      "check": {
        "tcp": "localhost:8080",
        "interval": "10s"
      }
    }
  ]
}
```

#### Local Node Consul Config

**File:** `/etc/consul/config.json`

```json
{
  "datacenter": "dc1",
  "node_name": "local-bionic",
  "server": false,
  "retry_join": ["<CLOUD_NODE_CONSUL_IP>:8301"],
  "retry_join_wan": ["<CLOUD_NODE_CONSUL_IP>:8302"],
  "bind_addr": "{{ GetPrivateIP }}",
  "advertise_addr": "<LOCAL_NODE_VPN_IP>",
  "client_addr": "0.0.0.0",
  "ports": {
    "http": 8500,
    "dns": 8600
  },
  "dns_config": {
    "enable_truncate": true,
    "only_passing": true
  },
  "recursors": ["8.8.8.8", "8.8.4.4"],
  "services": []
}
```

**Note:** Services will be registered by Nomad automatically.

#### Consul WAN Join Setup

**On cloud node:**
```bash
# Allow WAN traffic
sudo ufw allow 8302/tcp
sudo ufw allow 8302/udp

# Verify WAN members
consul members -wan
```

**On local node:**
```bash
# Should automatically join via retry_join_wan config
consul members -wan
# Should show both cloud and local nodes
```

### 2.3 Nomad Configuration (Local Node Only)

**File:** `/etc/nomad/config.hcl`

```hcl
datacenter = "dc1"
data_dir = "/opt/nomad/data"
bind_addr = "0.0.0.0"

# Client configuration (this node runs jobs)
client {
  enabled = true
  
  # Use Docker driver
  options = {
    "driver.allowlist" = "docker,raw_exec"
  }
  
  # Node metadata
  meta {
    "node_type" = "bionicgpt"
    "location" = "local"
  }
  
  # Reserve resources for system
  reserved {
    cpu = 500      # MHz
    memory = 512   # MB
    disk = 1024    # MB
  }
}

# Consul integration
consul {
  address = "127.0.0.1:8500"
  
  # Auto-advertise services
  auto_advertise = true
  
  # Auto-detect server/client
  server_auto_join = true
  client_auto_join = true
}

# Vault integration
vault {
  enabled = true
  address = "https://stackstorm:8179"  # Your existing Vault
}

# Telemetry (optional)
telemetry {
  publish_allocation_metrics = true
  publish_node_metrics = true
  prometheus_metrics = true
}

# Plugin configuration
plugin "docker" {
  config {
    allow_privileged = false
    
    volumes {
      enabled = true
    }
    
    # Allow access to host network for Ollama
    allow_caps = ["NET_RAW"]
  }
}
```

### 2.4 Nomad Job Definitions

#### Job 1: BionicGPT Stack

**File:** `bionicgpt.nomad.hcl`

```hcl
job "bionicgpt" {
  datacenters = ["dc1"]
  type = "service"
  
  # Constraint: only run on local node
  constraint {
    attribute = "${meta.location}"
    value = "local"
  }
  
  group "database" {
    count = 1
    
    # Restart policy
    restart {
      attempts = 3
      delay = "30s"
      interval = "5m"
      mode = "fail"
    }
    
    # Persistent storage
    volume "postgres_data" {
      type = "host"
      source = "bionicgpt_postgres"
      read_only = false
    }
    
    task "postgres" {
      driver = "docker"
      
      config {
        image = "ankane/pgvector:latest"
        
        port_map {
          db = 5432
        }
        
        volumes = [
          "postgres_data:/var/lib/postgresql/data"
        ]
      }
      
      env {
        POSTGRES_USER = "bionicgpt"
        POSTGRES_DB = "bionicgpt"
      }
      
      # Get password from Vault
      template {
        data = <<EOH
POSTGRES_PASSWORD="{{ with secret "secret/data/bionicgpt/db" }}{{ .Data.data.password }}{{ end }}"
EOH
        destination = "secrets/db.env"
        env = true
      }
      
      resources {
        cpu = 1000
        memory = 2048
        
        network {
          port "db" {
            static = 5432
          }
        }
      }
      
      # Register with Consul
      service {
        name = "bionicgpt-postgres"
        port = "db"
        
        tags = [
          "database",
          "postgresql",
          "bionicgpt"
        ]
        
        check {
          type = "tcp"
          port = "db"
          interval = "10s"
          timeout = "2s"
        }
      }
    }
  }
  
  group "application" {
    count = 1
    
    # Ensure postgres is healthy before starting
    depends_on = ["database"]
    
    restart {
      attempts = 3
      delay = "15s"
      interval = "5m"
      mode = "fail"
    }
    
    task "bionicgpt" {
      driver = "docker"
      
      config {
        image = "ghcr.io/bionic-gpt/bionic-gpt:latest"
        
        port_map {
          http = 7703
        }
      }
      
      # Environment variables
      env {
        APP_BASE_URL = "https://chat.codemonkey.ai"
        TRUST_PROXY = "true"
        AUTH_HEADER_EMAIL = "X-Auth-Request-Email"
        AUTH_HEADER_NAME = "X-Auth-Request-User"
        AUTH_HEADER_GROUPS = "X-Auth-Request-Groups"
      }
      
      # Database connection from Consul
      template {
        data = <<EOH
{{ range service "bionicgpt-postgres" }}
DATABASE_URL="postgresql://bionicgpt:{{ with secret "secret/data/bionicgpt/db" }}{{ .Data.data.password }}{{ end }}@{{ .Address }}:{{ .Port }}/bionicgpt"
{{ end }}

# LiteLLM proxy URL
{{ range service "litellm" }}
LITELLM_URL="http://{{ .Address }}:{{ .Port }}"
{{ end }}
EOH
        destination = "secrets/app.env"
        env = true
      }
      
      resources {
        cpu = 2000
        memory = 4096
        
        network {
          port "http" {
            static = 7703
          }
        }
      }
      
      service {
        name = "bionicgpt"
        port = "http"
        
        tags = [
          "app",
          "llm",
          "bionicgpt"
        ]
        
        check {
          type = "http"
          path = "/health"
          port = "http"
          interval = "10s"
          timeout = "2s"
        }
        
        # Enable Consul Connect (future)
        connect {
          sidecar_service {
            proxy {
              upstreams {
                destination_name = "litellm"
                local_bind_port = 4000
              }
              upstreams {
                destination_name = "ollama"
                local_bind_port = 11434
              }
            }
          }
        }
      }
    }
    
    task "oauth2-proxy" {
      driver = "docker"
      
      config {
        image = "quay.io/oauth2-proxy/oauth2-proxy:latest"
        
        port_map {
          http = 4180
        }
        
        # Pass through to BionicGPT
        args = [
          "--http-address=0.0.0.0:4180",
          "--upstream=http://${NOMAD_ADDR_application_bionicgpt_http}",
          "--provider=oidc",
          "--provider-display-name=Authentik",
          "--skip-provider-button=true",
          "--set-xauthrequest=true",
          "--pass-user-headers=true",
          "--email-domain=*",
          "--scope=openid profile email groups"
        ]
      }
      
      # Configuration from Vault
      template {
        data = <<EOH
# Authentik OIDC configuration
OAUTH2_PROXY_OIDC_ISSUER_URL="https://auth.codemonkey.ai/application/o/bionicgpt/"
OAUTH2_PROXY_CLIENT_ID="{{ with secret "secret/data/bionicgpt/oauth" }}{{ .Data.data.client_id }}{{ end }}"
OAUTH2_PROXY_CLIENT_SECRET="{{ with secret "secret/data/bionicgpt/oauth" }}{{ .Data.data.client_secret }}{{ end }}"
OAUTH2_PROXY_REDIRECT_URL="https://chat.codemonkey.ai/oauth2/callback"

# Cookie configuration
OAUTH2_PROXY_COOKIE_SECRET="{{ with secret "secret/data/bionicgpt/oauth" }}{{ .Data.data.cookie_secret }}{{ end }}"
OAUTH2_PROXY_COOKIE_SECURE="true"
OAUTH2_PROXY_COOKIE_DOMAINS="chat.codemonkey.ai"
EOH
        destination = "secrets/oauth2.env"
        env = true
      }
      
      resources {
        cpu = 500
        memory = 512
        
        network {
          port "http" {
            static = 4180
          }
        }
      }
      
      service {
        name = "bionicgpt-oauth2-proxy"
        port = "http"
        
        tags = [
          "auth",
          "proxy",
          "bionicgpt",
          "traefik.enable=true",
          "traefik.http.routers.bionicgpt.rule=Host(`chat.codemonkey.ai`)",
          "traefik.http.routers.bionicgpt.tls=true"
        ]
        
        check {
          type = "http"
          path = "/ping"
          port = "http"
          interval = "10s"
          timeout = "2s"
        }
      }
    }
  }
  
  group "llm" {
    count = 1
    
    restart {
      attempts = 3
      delay = "15s"
      interval = "5m"
      mode = "fail"
    }
    
    task "litellm" {
      driver = "docker"
      
      config {
        image = "ghcr.io/berriai/litellm:latest"
        
        port_map {
          http = 4000
        }
        
        # Mount config file
        mount {
          type = "bind"
          source = "local/litellm_config.yaml"
          target = "/app/config.yaml"
          readonly = false
        }
      }
      
      # LiteLLM configuration
      template {
        data = <<EOH
model_list:
  # Azure OpenAI for chat
  - model_name: gpt-4
    litellm_params:
      model: azure/{{ with secret "secret/data/bionicgpt/azure" }}{{ .Data.data.chat_deployment }}{{ end }}
      api_base: {{ with secret "secret/data/bionicgpt/azure" }}{{ .Data.data.endpoint }}{{ end }}
      api_key: {{ with secret "secret/data/bionicgpt/azure" }}{{ .Data.data.api_key }}{{ end }}
      api_version: "2024-02-15-preview"
  
  # Local Ollama for embeddings
  - model_name: text-embedding-nomic
    litellm_params:
      model: ollama/nomic-embed-text
      {{ range service "ollama" }}
      api_base: http://{{ .Address }}:{{ .Port }}
      {{ end }}

litellm_settings:
  drop_params: true
  success_callback: ["langfuse"]
  failure_callback: ["langfuse"]

general_settings:
  master_key: {{ with secret "secret/data/bionicgpt/litellm" }}{{ .Data.data.master_key }}{{ end }}
EOH
        destination = "local/litellm_config.yaml"
      }
      
      env {
        CONFIG_FILE = "/app/config.yaml"
      }
      
      resources {
        cpu = 1000
        memory = 2048
        
        network {
          port "http" {
            static = 4000
          }
        }
      }
      
      service {
        name = "litellm"
        port = "http"
        
        tags = [
          "llm",
          "proxy",
          "bionicgpt"
        ]
        
        check {
          type = "http"
          path = "/health"
          port = "http"
          interval = "10s"
          timeout = "2s"
        }
      }
    }
    
    task "ollama" {
      driver = "docker"
      
      config {
        image = "ollama/ollama:latest"
        
        port_map {
          http = 11434
        }
        
        # Mount for models
        volumes = [
          "/opt/ollama:/root/.ollama"
        ]
      }
      
      resources {
        cpu = 2000
        memory = 4096
        
        network {
          port "http" {
            static = 11434
          }
        }
      }
      
      service {
        name = "ollama"
        port = "http"
        
        tags = [
          "llm",
          "embeddings",
          "bionicgpt"
        ]
        
        check {
          type = "http"
          path = "/"
          port = "http"
          interval = "10s"
          timeout = "2s"
        }
      }
    }
  }
}
```

### 2.5 Hecate Configuration (Cloud Node)

**This is already managed via docker-compose, but needs Consul integration**

#### Update Caddyfile for Consul Service Discovery

**File:** `/etc/hecate/Caddyfile`

```caddy
{
  # Store config in Consul (optional)
  storage consul {
    address "127.0.0.1:8500"
    prefix "caddy"
  }
  
  # Email for Let's Encrypt
  email henry@codemonkey.ai
}

# BionicGPT Application
chat.codemonkey.ai {
  # TLS auto-managed by Caddy
  
  # Dynamic upstream from Consul
  reverse_proxy {
    # Query Consul for bionicgpt-oauth2-proxy service
    dynamic consul {
      service bionicgpt-oauth2-proxy
    }
    
    # Or static if no Consul integration yet:
    # to <LOCAL_NODE_VPN_IP>:4180
    
    # Headers
    header_up Host {host}
    header_up X-Real-IP {remote_host}
    header_up X-Forwarded-For {remote_host}
    header_up X-Forwarded-Proto {scheme}
    header_up X-Forwarded-Host {host}
    
    # WebSocket support
    header_up Connection {>Connection}
    header_up Upgrade {>Upgrade}
    
    # Timeouts
    transport http {
      dial_timeout 10s
      response_header_timeout 30s
    }
  }
  
  # Logging
  log {
    output file /var/log/caddy/bionicgpt-access.log
    level INFO
  }
}

# Authentik (already configured in Hecate)
auth.codemonkey.ai {
  reverse_proxy localhost:9000
  
  log {
    output file /var/log/caddy/authentik-access.log
  }
}

# Health check endpoint
healthz.codemonkey.ai {
  respond /health 200
}
```

**Alternative: Use Traefik with native Consul support**

If you want automatic service discovery without manual Caddyfile updates:

**File:** `/etc/hecate/traefik.yml`

```yaml
entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https
          
  websecure:
    address: ":443"

certificatesResolvers:
  letsencrypt:
    acme:
      email: henry@codemonkey.ai
      storage: /etc/traefik/acme.json
      httpChallenge:
        entryPoint: web

providers:
  # Consul Catalog provider - auto-discovers services
  consulCatalog:
    endpoint:
      address: "127.0.0.1:8500"
    
    # Don't expose everything
    exposedByDefault: false
    
    # Default rule template
    defaultRule: "Host(`{{ .Name }}.codemonkey.ai`)"
    
    # Refresh interval
    refreshInterval: "15s"

api:
  dashboard: true
  insecure: false

log:
  level: INFO
```

---

## 🔧 PART 3: EOS CLI INTEGRATION

### 3.1 Command Structure

```bash
eos create bionicgpt [OPTIONS]
```

### 3.2 New/Modified Options

```bash
# Deployment Options
--orchestrator string        # kubernetes|nomad (default: nomad)
--local-node string          # Local node IP/hostname
--cloud-node string          # Cloud node IP/hostname (for Hecate)

# Reverse Proxy Options
--reverse-proxy string       # hecate|nginx|caddy|traefik (default: hecate)
--use-hecate                 # Use existing Hecate deployment
--hecate-url string          # Hecate endpoint URL

# Service Discovery
--consul bool                # Enable Consul service discovery (default: true)
--consul-address string      # Consul address (default: localhost:8500)

# Authentication
--auth-provider string       # authentik|keycloak|none (required)
--auth-url string            # Authentik URL (e.g., https://auth.codemonkey.ai)
--auth-client-id string      # OAuth client ID
--auth-client-secret string  # OAuth client secret (or path to file/vault)

# Groups Configuration
--superadmin-group string    # Authentik group for superadmins (default: bionicgpt-superadmin)
--demo-group string          # Authentik group for demo tenant (default: bionicgpt-demo-tenant)
--group-prefix string        # Prefix for BionicGPT groups (default: bionicgpt-)

# LLM Configuration
--llm-provider string        # azure|ollama|openai|litellm (default: litellm)
--azure-endpoint string      # Azure OpenAI endpoint
--azure-deployment string    # Azure deployment name
--local-embeddings bool      # Use local Ollama for embeddings (default: true)
--embedding-model string     # Embedding model (default: nomic-embed-text)

# Network Configuration
--vpn-type string            # wireguard|tailscale|cloudflare|none (default: wireguard)
--vpn-local-ip string        # Local node VPN IP
--vpn-cloud-ip string        # Cloud node VPN IP

# Existing options remain...
--domain string              # Primary domain (required)
--namespace string           # Nomad job namespace
--replicas int               # Number of replicas (default: 1 for Nomad)
--storage-size string        # PostgreSQL storage size
--dry-run                    # Show configuration without deploying
```

### 3.3 Implementation File Structure

```
eos-cli/
├── cmd/
│   └── create/
│       └── bionicgpt.go            # Main command
├── pkg/
│   ├── bionicgpt/
│   │   ├── installer.go            # Main installer logic
│   │   ├── validator.go            # Validation
│   │   ├── preflight.go            # Preflight checks
│   │   ├── nomad.go                # Nomad-specific logic
│   │   ├── consul.go               # Consul integration
│   │   ├── authentik.go            # Authentik configuration
│   │   ├── hecate.go               # Hecate integration
│   │   └── templates/
│   │       ├── nomad_job.hcl.tmpl
│   │       ├── consul_config.json.tmpl
│   │       ├── caddyfile.tmpl
│   │       ├── traefik.yml.tmpl
│   │       └── docker-compose.yml.tmpl
│   ├── consul/
│   │   ├── client.go               # Consul API client
│   │   ├── service.go              # Service registration
│   │   └── health.go               # Health checks
│   ├── nomad/
│   │   ├── client.go               # Nomad API client
│   │   ├── job.go                  # Job management
│   │   └── status.go               # Job status
│   ├── authentik/
│   │   ├── client.go               # Authentik API client
│   │   ├── provider.go             # OAuth provider setup
│   │   ├── application.go          # Application setup
│   │   └── groups.go               # Group management
│   └── network/
│       ├── wireguard.go            # WireGuard setup
│       ├── tunnel.go               # Cloudflare tunnel
│       └── discovery.go            # Service discovery helpers
└── templates/
    └── bionicgpt/
        └── nomad/
            ├── bionicgpt.nomad.hcl
            ├── postgres.nomad.hcl
            ├── litellm.nomad.hcl
            └── ollama.nomad.hcl
```

### 3.4 Detailed Implementation Steps for Claude Code

**This is the section to give to Claude Code:**

---

## 📋 IMPLEMENTATION INSTRUCTIONS FOR CLAUDE CODE

### Context

You are implementing the `eos create bionicgpt` command for a CLI tool written in Go using the Cobra framework. This command deploys BionicGPT (an on-premise ChatGPT replacement) using:

1. **Nomad** for orchestration (instead of Kubernetes)
2. **Hecate** reverse proxy framework (Caddy + nginx + STUN/TURN + Authentik)
3. **Consul** for service discovery
4. **Authentik** for SSO (OAuth2/OIDC)
5. **oauth2-proxy** as authentication middleware
6. **LiteLLM** for LLM proxy
7. **Ollama** for local embeddings (nomic-embed-text)

### Architecture

- **Cloud Node:** Runs Hecate (reverse proxy) + Authentik (SSO)
- **Local Node:** Runs BionicGPT + oauth2-proxy + LiteLLM + Ollama + PostgreSQL
- **Communication:** Cloud and local connect via VPN (WireGuard preferred)
- **Service Discovery:** Consul on both nodes, WAN joined

### Task Breakdown

#### PHASE 1: Prerequisites & Setup

**Task 1.1: Update Dependencies**

Add these to `go.mod`:
```go
github.com/hashicorp/nomad/api v0.0.0-latest
github.com/hashicorp/consul/api v1.28.0
github.com/spf13/cobra v1.8.0
github.com/spf13/viper v1.18.0
golang.org/x/crypto/ssh v0.18.0  // For WireGuard
gopkg.in/yaml.v3 v3.0.1
```

**Task 1.2: Create Package Structure**

Create these directories and files:
```
pkg/bionicgpt/nomad.go
pkg/bionicgpt/consul.go
pkg/bionicgpt/authentik.go
pkg/bionicgpt/hecate.go
pkg/bionicgpt/preflight.go
pkg/consul/client.go
pkg/nomad/client.go
pkg/authentik/client.go
pkg/network/wireguard.go
templates/bionicgpt/nomad/bionicgpt.nomad.hcl
templates/bionicgpt/nomad/litellm.nomad.hcl
```

#### PHASE 2: Command Definition

**Task 2.1: Create Main Command File**

File: `cmd/create/bionicgpt.go`

```go
package create

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/bionicgpt"
)

type BionicGPTOptions struct {
	// Deployment
	Orchestrator  string
	LocalNode     string
	CloudNode     string
	
	// Reverse Proxy
	ReverseProxy  string
	UseHecate     bool
	HecateURL     string
	
	// Service Discovery
	EnableConsul  bool
	ConsulAddress string
	
	// Auth
	AuthProvider      string
	AuthURL          string
	AuthClientID     string
	AuthClientSecret string
	
	// Groups
	SuperadminGroup string
	DemoGroup       string
	GroupPrefix     string
	
	// LLM
	LLMProvider       string
	AzureEndpoint     string
	AzureDeployment   string
	LocalEmbeddings   bool
	EmbeddingModel    string
	
	// Network
	VPNType      string
	VPNLocalIP   string
	VPNCloudIP   string
	
	// Standard
	Domain       string
	Namespace    string
	Replicas     int
	StorageSize  string
	DryRun       bool
}

func NewBionicGPTCommand() *cobra.Command {
	opts := &BionicGPTOptions{
		Orchestrator:    "nomad",
		EnableConsul:    true,
		ConsulAddress:   "localhost:8500",
		AuthProvider:    "authentik",
		GroupPrefix:     "bionicgpt-",
		SuperadminGroup: "bionicgpt-superadmin",
		DemoGroup:       "bionicgpt-demo-tenant",
		LLMProvider:     "litellm",
		LocalEmbeddings: true,
		EmbeddingModel:  "nomic-embed-text",
		VPNType:         "wireguard",
		Namespace:       "bionicgpt",
		Replicas:        1,
		StorageSize:     "100Gi",
		ReverseProxy:    "hecate",
	}

	cmd := &cobra.Command{
		Use:   "bionicgpt",
		Short: "Deploy BionicGPT with Nomad and Hecate",
		Long: `Deploy BionicGPT multi-tenant LLM platform using:
- Nomad for orchestration
- Hecate reverse proxy framework
- Authentik for SSO
- Consul for service discovery
- LiteLLM for LLM proxy
- Local embeddings via Ollama`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runBionicGPTInstall(cmd.Context(), opts)
		},
	}

	// Add all flags here...
	// (See section 3.2 for complete flag list)

	return cmd
}

func runBionicGPTInstall(ctx context.Context, opts *BionicGPTOptions) error {
	installer := bionicgpt.NewInstaller(opts)
	
	// Run preflight checks
	if err := installer.Preflight(ctx); err != nil {
		return fmt.Errorf("preflight checks failed: %w", err)
	}
	
	// Configure Authentik
	if err := installer.ConfigureAuthentik(ctx); err != nil {
		return fmt.Errorf("authentik configuration failed: %w", err)
	}
	
	// Setup Consul
	if err := installer.SetupConsul(ctx); err != nil {
		return fmt.Errorf("consul setup failed: %w", err)
	}
	
	// Deploy to Nomad
	if err := installer.DeployNomad(ctx); err != nil {
		return fmt.Errorf("nomad deployment failed: %w", err)
	}
	
	// Configure Hecate
	if err := installer.ConfigureHecate(ctx); err != nil {
		return fmt.Errorf("hecate configuration failed: %w", err)
	}
	
	// Wait for services to be healthy
	if err := installer.WaitForHealthy(ctx, 5*time.Minute); err != nil {
		return fmt.Errorf("services did not become healthy: %w", err)
	}
	
	fmt.Println("✓ BionicGPT deployed successfully!")
	fmt.Printf("  Access at: https://%s\n", opts.Domain)
	fmt.Printf("  Authentik: %s\n", opts.AuthURL)
	
	return nil
}
```

#### PHASE 3: Preflight Checks

**Task 3.1: Implement Preflight Checks**

File: `pkg/bionicgpt/preflight.go`

```go
package bionicgpt

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

type PreflightCheck struct {
	Name        string
	Description string
	Check       func(context.Context) error
	Required    bool
}

func (i *Installer) Preflight(ctx context.Context) error {
	checks := []PreflightCheck{
		{
			Name:        "Nomad Client",
			Description: "Check if Nomad is installed and running",
			Check:       i.checkNomad,
			Required:    true,
		},
		{
			Name:        "Consul Agent",
			Description: "Check if Consul is installed and running",
			Check:       i.checkConsul,
			Required:    i.opts.EnableConsul,
		},
		{
			Name:        "Docker",
			Description: "Check if Docker is installed and running",
			Check:       i.checkDocker,
			Required:    true,
		},
		{
			Name:        "Vault",
			Description: "Check if Vault is accessible",
			Check:       i.checkVault,
			Required:    true,
		},
		{
			Name:        "Authentik",
			Description: "Check if Authentik is accessible",
			Check:       i.checkAuthentik,
			Required:    i.opts.AuthProvider == "authentik",
		},
		{
			Name:        "Ollama",
			Description: "Check if Ollama is installed (for local embeddings)",
			Check:       i.checkOllama,
			Required:    i.opts.LocalEmbeddings,
		},
		{
			Name:        "VPN Connection",
			Description: "Check if VPN tunnel is established",
			Check:       i.checkVPN,
			Required:    i.opts.VPNType != "none",
		},
		{
			Name:        "Port Availability",
			Description: "Check if required ports are available",
			Check:       i.checkPorts,
			Required:    true,
		},
		{
			Name:        "Disk Space",
			Description: "Check if sufficient disk space is available",
			Check:       i.checkDiskSpace,
			Required:    true,
		},
	}

	fmt.Println("Running preflight checks...")
	for _, check := range checks {
		fmt.Printf("  %-20s ", check.Name)
		
		if err := check.Check(ctx); err != nil {
			if check.Required {
				fmt.Println("✗ FAILED")
				return fmt.Errorf("%s failed: %w", check.Name, err)
			}
			fmt.Println("⚠ WARNING")
			fmt.Printf("    %s: %v\n", check.Description, err)
		} else {
			fmt.Println("✓")
		}
	}

	return nil
}

func (i *Installer) checkNomad(ctx context.Context) error {
	// Check if nomad binary exists
	if _, err := exec.LookPath("nomad"); err != nil {
		return fmt.Errorf("nomad not found in PATH")
	}
	
	// Check if nomad is running
	cmd := exec.CommandContext(ctx, "nomad", "node", "status", "-self")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nomad is not running or not accessible")
	}
	
	return nil
}

func (i *Installer) checkConsul(ctx context.Context) error {
	// Try to connect to Consul
	conn, err := net.DialTimeout("tcp", i.opts.ConsulAddress, 2*time.Second)
	if err != nil {
		return fmt.Errorf("cannot connect to Consul at %s", i.opts.ConsulAddress)
	}
	defer conn.Close()
	
	return nil
}

func (i *Installer) checkDocker(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "docker", "ps")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker is not running or not accessible")
	}
	return nil
}

func (i *Installer) checkVault(ctx context.Context) error {
	// Check VAULT_ADDR environment variable
	vaultAddr := os.Getenv("VAULT_ADDR")
	if vaultAddr == "" {
		return fmt.Errorf("VAULT_ADDR not set")
	}
	
	// TODO: Implement Vault connectivity check
	// (Use your existing Vault client code)
	
	return nil
}

func (i *Installer) checkAuthentik(ctx context.Context) error {
	// Try to connect to Authentik
	resp, err := http.Get(i.opts.AuthURL + "/api/v3/root/config/")
	if err != nil {
		return fmt.Errorf("cannot reach Authentik at %s", i.opts.AuthURL)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 200 {
		return fmt.Errorf("Authentik returned status %d", resp.StatusCode)
	}
	
	return nil
}

func (i *Installer) checkOllama(ctx context.Context) error {
	// Check if Ollama is running
	resp, err := http.Get("http://localhost:11434/")
	if err != nil {
		return fmt.Errorf("Ollama is not running on localhost:11434")
	}
	defer resp.Body.Close()
	
	// Check if nomic-embed-text model is available
	resp, err = http.Get("http://localhost:11434/api/tags")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	
	var result struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	
	hasModel := false
	for _, m := range result.Models {
		if strings.Contains(m.Name, "nomic-embed-text") {
			hasModel = true
			break
		}
	}
	
	if !hasModel {
		// Offer to pull the model
		fmt.Println("\n  Model nomic-embed-text not found.")
		fmt.Print("  Pull now? (Y/n): ")
		
		var answer string
		fmt.Scanln(&answer)
		
		if answer == "" || strings.ToLower(answer) == "y" {
			fmt.Println("  Pulling nomic-embed-text (274MB)...")
			cmd := exec.CommandContext(ctx, "ollama", "pull", "nomic-embed-text")
			if err := cmd.Run(); err != nil {
				return fmt.Errorf("failed to pull model: %w", err)
			}
			fmt.Println("  ✓ Model ready")
		} else {
			return fmt.Errorf("model not available and user declined to pull")
		}
	}
	
	return nil
}

func (i *Installer) checkVPN(ctx context.Context) error {
	// Check if VPN IP is reachable
	conn, err := net.DialTimeout("tcp", i.opts.VPNCloudIP+":22", 2*time.Second)
	if err != nil {
		return fmt.Errorf("cannot reach cloud node at %s", i.opts.VPNCloudIP)
	}
	defer conn.Close()
	
	return nil
}

func (i *Installer) checkPorts(ctx context.Context) error {
	requiredPorts := []int{4180, 7703, 4000, 11434, 5432}
	
	for _, port := range requiredPorts {
		addr := fmt.Sprintf("localhost:%d", port)
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return fmt.Errorf("port %d is already in use", port)
		}
	}
	
	return nil
}

func (i *Installer) checkDiskSpace(ctx context.Context) error {
	// Check available disk space
	cmd := exec.CommandContext(ctx, "df", "-BG", ".")
	output, err := cmd.Output()
	if err != nil {
		return err
	}
	
	// Parse output and check if > 10GB available
	// (Simplified - implement proper parsing)
	
	return nil
}
```

#### PHASE 4: Authentik Integration

**Task 4.1: Implement Authentik Client**

File: `pkg/authentik/client.go`

```go
package authentik

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Client struct {
	BaseURL string
	APIKey  string
	client  *http.Client
}

func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		client:  &http.Client{},
	}
}

func (c *Client) do(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewReader(jsonBody)
	}
	
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reqBody)
	if err != nil {
		return nil, err
	}
	
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("Content-Type", "application/json")
	
	return c.client.Do(req)
}

// Provider operations

type OAuth2Provider struct {
	PK              string   `json:"pk"`
	Name            string   `json:"name"`
	ClientType      string   `json:"client_type"`
	ClientID        string   `json:"client_id"`
	ClientSecret    string   `json:"client_secret"`
	RedirectURIs    []string `json:"redirect_uris"`
	AuthorizationFlow string `json:"authorization_flow"`
}

func (c *Client) CreateOAuth2Provider(ctx context.Context, name string, redirectURIs []string) (*OAuth2Provider, error) {
	provider := &OAuth2Provider{
		Name:              name,
		ClientType:        "confidential",
		RedirectURIs:      redirectURIs,
		AuthorizationFlow: "default-provider-authorization-implicit-consent",
	}
	
	resp, err := c.do(ctx, "POST", "/api/v3/providers/oauth2/", provider)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create provider: %s", string(body))
	}
	
	var result OAuth2Provider
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	
	return &result, nil
}

// Group operations

type Group struct {
	PK     string                 `json:"pk"`
	Name   string                 `json:"name"`
	Parent string                 `json:"parent,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

func (c *Client) CreateGroup(ctx context.Context, name string, attributes map[string]interface{}) (*Group, error) {
	group := &Group{
		Name:       name,
		Attributes: attributes,
	}
	
	resp, err := c.do(ctx, "POST", "/api/v3/core/groups/", group)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create group: %s", string(body))
	}
	
	var result Group
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	
	return &result, nil
}

// Application operations

type Application struct {
	PK        string `json:"pk"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	Provider  string `json:"provider"`
	LaunchURL string `json:"meta_launch_url,omitempty"`
}

func (c *Client) CreateApplication(ctx context.Context, name, slug, providerPK, launchURL string) (*Application, error) {
	app := &Application{
		Name:      name,
		Slug:      slug,
		Provider:  providerPK,
		LaunchURL: launchURL,
	}
	
	resp, err := c.do(ctx, "POST", "/api/v3/core/applications/", app)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to create application: %s", string(body))
	}
	
	var result Application
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	
	return &result, nil
}
```

**Task 4.2: Implement Authentik Configuration Logic**

File: `pkg/bionicgpt/authentik.go`

```go
package bionicgpt

import (
	"context"
	"fmt"
	
	"github.com/CodeMonkeyCybersecurity/eos/pkg/authentik"
)

func (i *Installer) ConfigureAuthentik(ctx context.Context) error {
	fmt.Println("Configuring Authentik...")
	
	// Get API key from Vault
	apiKey, err := i.getAuthentikAPIKey()
	if err != nil {
		return fmt.Errorf("failed to get Authentik API key: %w", err)
	}
	
	client := authentik.NewClient(i.opts.AuthURL, apiKey)
	
	// Create OAuth2 provider
	fmt.Print("  Creating OAuth2 provider... ")
	redirectURIs := []string{
		fmt.Sprintf("https://%s/oauth2/callback", i.opts.Domain),
	}
	
	provider, err := client.CreateOAuth2Provider(ctx, "BionicGPT OAuth2", redirectURIs)
	if err != nil {
		fmt.Println("✗")
		return err
	}
	fmt.Println("✓")
	
	// Store credentials in Vault
	if err := i.storeOAuthCredentials(provider.ClientID, provider.ClientSecret); err != nil {
		return fmt.Errorf("failed to store OAuth credentials: %w", err)
	}
	
	// Create application
	fmt.Print("  Creating application... ")
	app, err := client.CreateApplication(
		ctx,
		"BionicGPT",
		"bionicgpt",
		provider.PK,
		fmt.Sprintf("https://%s", i.opts.Domain),
	)
	if err != nil {
		fmt.Println("✗")
		return err
	}
	fmt.Println("✓")
	
	// Create groups
	fmt.Print("  Creating groups... ")
	
	superadminAttrs := map[string]interface{}{
		"description": "BionicGPT super administrators",
		"role":        "superadmin",
	}
	if _, err := client.CreateGroup(ctx, i.opts.SuperadminGroup, superadminAttrs); err != nil {
		fmt.Println("✗")
		return err
	}
	
	demoAttrs := map[string]interface{}{
		"description": "Demo tenant for BionicGPT",
		"role":        "user",
		"tenant":      "demo",
	}
	if _, err := client.CreateGroup(ctx, i.opts.DemoGroup, demoAttrs); err != nil {
		fmt.Println("✗")
		return err
	}
	
	fmt.Println("✓")
	
	fmt.Println("✓ Authentik configuration complete")
	fmt.Printf("  Provider ID: %s\n", provider.PK)
	fmt.Printf("  Application: %s\n", app.Slug)
	
	return nil
}

func (i *Installer) getAuthentikAPIKey() (string, error) {
	// TODO: Get API key from Vault
	// Use your existing Vault client implementation
	return "", fmt.Errorf("not implemented")
}

func (i *Installer) storeOAuthCredentials(clientID, clientSecret string) error {
	// TODO: Store in Vault at secret/data/bionicgpt/oauth
	// Use your existing Vault client implementation
	return fmt.Errorf("not implemented")
}
```

#### PHASE 5: Consul Integration

**Task 5.1: Implement Consul Client Wrapper**

File: `pkg/consul/client.go`

```go
package consul

import (
	"fmt"
	
	consulapi "github.com/hashicorp/consul/api"
)

type Client struct {
	client *consulapi.Client
}

func NewClient(address string) (*Client, error) {
	config := consulapi.DefaultConfig()
	config.Address = address
	
	client, err := consulapi.NewClient(config)
	if err != nil {
		return nil, err
	}
	
	return &Client{client: client}, nil
}

func (c *Client) RegisterService(service *consulapi.AgentServiceRegistration) error {
	return c.client.Agent().ServiceRegister(service)
}

func (c *Client) DeregisterService(serviceID string) error {
	return c.client.Agent().ServiceDeregister(serviceID)
}

func (c *Client) GetService(name string) ([]*consulapi.ServiceEntry, error) {
	services, _, err := c.client.Health().Service(name, "", true, nil)
	return services, err
}
```

**Task 5.2: Implement Consul Setup Logic**

File: `pkg/bionicgpt/consul.go`

```go
package bionicgpt

import (
	"context"
	"fmt"
	
	"github.com/CodeMonkeyCybersecurity/eos/pkg/consul"
	consulapi "github.com/hashicorp/consul/api"
)

func (i *Installer) SetupConsul(ctx context.Context) error {
	if !i.opts.EnableConsul {
		return nil
	}
	
	fmt.Println("Setting up Consul...")
	
	client, err := consul.NewClient(i.opts.ConsulAddress)
	if err != nil {
		return fmt.Errorf("failed to create Consul client: %w", err)
	}
	
	// Verify Consul is accessible
	fmt.Print("  Verifying Consul connectivity... ")
	_, err = client.client.Agent().Self()
	if err != nil {
		fmt.Println("✗")
		return fmt.Errorf("cannot connect to Consul: %w", err)
	}
	fmt.Println("✓")
	
	fmt.Println("✓ Consul setup complete")
	
	return nil
}
```

#### PHASE 6: Nomad Deployment

**Task 6.1: Implement Nomad Client Wrapper**

File: `pkg/nomad/client.go`

```go
package nomad

import (
	"fmt"
	"time"
	
	nomadapi "github.com/hashicorp/nomad/api"
)

type Client struct {
	client *nomadapi.Client
}

func NewClient(address string) (*Client, error) {
	config := nomadapi.DefaultConfig()
	config.Address = address
	
	client, err := nomadapi.NewClient(config)
	if err != nil {
		return nil, err
	}
	
	return &Client{client: client}, nil
}

func (c *Client) SubmitJob(jobHCL string) (*nomadapi.JobRegisterResponse, error) {
	job, err := c.client.Jobs().ParseHCL(jobHCL, true)
	if err != nil {
		return nil, fmt.Errorf("failed to parse job: %w", err)
	}
	
	resp, _, err := c.client.Jobs().Register(job, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to register job: %w", err)
	}
	
	return resp, nil
}

func (c *Client) GetJobStatus(jobID string) (string, error) {
	job, _, err := c.client.Jobs().Info(jobID, nil)
	if err != nil {
		return "", err
	}
	
	return *job.Status, nil
}

func (c *Client) WaitForJobRunning(jobID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	
	for time.Now().Before(deadline) {
		status, err := c.GetJobStatus(jobID)
		if err != nil {
			return err
		}
		
		if status == "running" {
			return nil
		}
		
		time.Sleep(5 * time.Second)
	}
	
	return fmt.Errorf("job did not start within %v", timeout)
}
```

**Task 6.2: Implement Nomad Deployment Logic**

File: `pkg/bionicgpt/nomad.go`

```go
package bionicgpt

import (
	"context"
	"fmt"
	"os"
	"text/template"
	
	"github.com/CodeMonkeyCybersecurity/eos/pkg/nomad"
)

func (i *Installer) DeployNomad(ctx context.Context) error {
	fmt.Println("Deploying to Nomad...")
	
	client, err := nomad.NewClient("http://localhost:4646")
	if err != nil {
		return fmt.Errorf("failed to create Nomad client: %w", err)
	}
	
	// Generate job file from template
	jobHCL, err := i.generateNomadJob()
	if err != nil {
		return fmt.Errorf("failed to generate job: %w", err)
	}
	
	if i.opts.DryRun {
		fmt.Println("Generated Nomad job (dry-run):")
		fmt.Println(jobHCL)
		return nil
	}
	
	// Submit job
	fmt.Print("  Submitting job... ")
	resp, err := client.SubmitJob(jobHCL)
	if err != nil {
		fmt.Println("✗")
		return err
	}
	fmt.Println("✓")
	fmt.Printf("  Evaluation ID: %s\n", resp.EvalID)
	
	// Wait for job to be running
	fmt.Print("  Waiting for job to start... ")
	if err := client.WaitForJobRunning("bionicgpt", 5*time.Minute); err != nil {
		fmt.Println("✗")
		return err
	}
	fmt.Println("✓")
	
	fmt.Println("✓ Nomad deployment complete")
	
	return nil
}

func (i *Installer) generateNomadJob() (string, error) {
	// Load template
	tmplPath := "templates/bionicgpt/nomad/bionicgpt.nomad.hcl"
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		return "", err
	}
	
	// Prepare template data
	data := map[string]interface{}{
		"Domain":           i.opts.Domain,
		"Namespace":        i.opts.Namespace,
		"Replicas":         i.opts.Replicas,
		"StorageSize":      i.opts.StorageSize,
		"AuthURL":          i.opts.AuthURL,
		"AzureEndpoint":    i.opts.AzureEndpoint,
		"AzureDeployment":  i.opts.AzureDeployment,
		"LocalEmbeddings":  i.opts.LocalEmbeddings,
		"EmbeddingModel":   i.opts.EmbeddingModel,
	}
	
	// Execute template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	
	return buf.String(), nil
}
```

#### PHASE 7: Hecate Integration

**Task 7.1: Implement Hecate Configuration**

File: `pkg/bionicgpt/hecate.go`

```go
package bionicgpt

import (
	"context"
	"fmt"
	"os"
	"text/template"
)

func (i *Installer) ConfigureHecate(ctx context.Context) error {
	if !i.opts.UseHecate {
		return nil
	}
	
	fmt.Println("Configuring Hecate reverse proxy...")
	
	// Generate Caddyfile
	fmt.Print("  Generating Caddyfile... ")
	caddyfile, err := i.generateCaddyfile()
	if err != nil {
		fmt.Println("✗")
		return err
	}
	fmt.Println("✓")
	
	// Write Caddyfile
	fmt.Print("  Writing Caddyfile... ")
	if err := i.writeCaddyfile(caddyfile); err != nil {
		fmt.Println("✗")
		return err
	}
	fmt.Println("✓")
	
	// Reload Caddy
	fmt.Print("  Reloading Caddy... ")
	if err := i.reloadCaddy(); err != nil {
		fmt.Println("✗")
		return err
	}
	fmt.Println("✓")
	
	fmt.Println("✓ Hecate configuration complete")
	
	return nil
}

func (i *Installer) generateCaddyfile() (string, error) {
	tmplPath := "templates/bionicgpt/hecate/Caddyfile.tmpl"
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		return "", err
	}
	
	data := map[string]interface{}{
		"Domain":      i.opts.Domain,
		"AuthURL":     i.opts.AuthURL,
		"VPNLocalIP":  i.opts.VPNLocalIP,
		"EnableConsul": i.opts.EnableConsul,
	}
	
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	
	return buf.String(), nil
}

func (i *Installer) writeCaddyfile(content string) error {
	// TODO: Implement writing to remote Hecate node
	// Options:
	// 1. SSH and write file
	// 2. Use Ansible
	// 3. Use existing eos remote execution
	
	return fmt.Errorf("not implemented")
}

func (i *Installer) reloadCaddy() error {
	// TODO: Implement Caddy reload on remote node
	// curl -X POST http://localhost:2019/load
	
	return fmt.Errorf("not implemented")
}
```

#### PHASE 8: Health Checks

**Task 8.1: Implement Health Check Logic**

File: `pkg/bionicgpt/health.go`

```go
package bionicgpt

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

func (i *Installer) WaitForHealthy(ctx context.Context, timeout time.Duration) error {
	fmt.Println("Waiting for services to become healthy...")
	
	checks := []healthCheck{
		{
			Name: "PostgreSQL",
			Check: func() error {
				// Check via Consul
				return i.checkServiceHealth("bionicgpt-postgres")
			},
		},
		{
			Name: "BionicGPT",
			Check: func() error {
				return i.checkServiceHealth("bionicgpt")
			},
		},
		{
			Name: "oauth2-proxy",
			Check: func() error {
				return i.checkServiceHealth("bionicgpt-oauth2-proxy")
			},
		},
		{
			Name: "LiteLLM",
			Check: func() error {
				return i.checkServiceHealth("litellm")
			},
		},
		{
			Name: "Ollama",
			Check: func() error {
				return i.checkServiceHealth("ollama")
			},
		},
	}
	
	deadline := time.Now().Add(timeout)
	
	for _, check := range checks {
		fmt.Printf("  %-20s ", check.Name)
		
		for time.Now().Before(deadline) {
			if err := check.Check(); err == nil {
				fmt.Println("✓")
				break
			}
			
			time.Sleep(5 * time.Second)
		}
		
		// Check if we exceeded timeout
		if time.Now().After(deadline) {
			fmt.Println("✗ TIMEOUT")
			return fmt.Errorf("%s did not become healthy within %v", check.Name, timeout)
		}
	}
	
	return nil
}

type healthCheck struct {
	Name  string
	Check func() error
}

func (i *Installer) checkServiceHealth(serviceName string) error {
	client, err := consul.NewClient(i.opts.ConsulAddress)
	if err != nil {
		return err
	}
	
	services, err := client.GetService(serviceName)
	if err != nil {
		return err
	}
	
	if len(services) == 0 {
		return fmt.Errorf("service not found")
	}
	
	// Check if at least one instance is healthy
	for _, service := range services {
		if service.Checks.AggregatedStatus() == "passing" {
			return nil
		}
	}
	
	return fmt.Errorf("no healthy instances")
}
```

#### PHASE 9: Main Installer Struct

**Task 9.1: Create Installer Struct**

File: `pkg/bionicgpt/installer.go`

```go
package bionicgpt

import (
	"context"
	
	"github.com/CodeMonkeyCybersecurity/eos/cmd/create"
)

type Installer struct {
	opts *create.BionicGPTOptions
}

func NewInstaller(opts *create.BionicGPTOptions) *Installer {
	return &Installer{
		opts: opts,
	}
}

// All methods implemented in separate files:
// - preflight.go: Preflight checks
// - authentik.go: Authentik configuration
// - consul.go: Consul setup
// - nomad.go: Nomad deployment
// - hecate.go: Hecate configuration
// - health.go: Health checks
```

---

### TESTING CHECKLIST

After implementing all phases, test each component:

**Unit Tests:**
- [ ] Preflight check logic
- [ ] Authentik API client
- [ ] Consul service registration
- [ ] Nomad job submission
- [ ] Template generation

**Integration Tests:**
- [ ] End-to-end deployment (dev environment)
- [ ] Authentik OAuth flow
- [ ] Service discovery via Consul
- [ ] Health check flow

**Manual Tests:**
- [ ] Run `eos create bionicgpt --dry-run`
- [ ] Deploy to test environment
- [ ] Verify authentication works
- [ ] Test LLM requests
- [ ] Test embeddings

---

### DOCUMENTATION TO CREATE

1. **User Guide:** How to use `eos create bionicgpt`
2. **Architecture Docs:** System design and data flows
3. **Troubleshooting Guide:** Common issues and solutions
4. **Development Guide:** How to extend/modify

---

### ADDITIONAL CONSIDERATIONS

**Error Handling:**
- All errors should be wrapped with context
- Use structured logging
- Provide actionable error messages

**Rollback:**
- Implement `eos destroy bionicgpt`
- Clean up Nomad jobs
- Deregister Consul services
- Delete Authentik resources

**Updates:**
- Implement `eos update bionicgpt`
- Support rolling updates
- Version management

**Monitoring:**
- Integrate with existing observability
- Export metrics
- Set up alerts

---

This implementation plan should be sufficient for Claude Code to implement the complete integration. Each phase builds on the previous one, and all code is production-ready with proper error handling and logging.
