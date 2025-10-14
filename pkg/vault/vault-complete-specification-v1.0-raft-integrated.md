# EOS Vault Complete Specification v1.0
## Production-Ready Vault Deployment with Integrated Storage (Raft)

**Version:** 1.0 (Raft-Integrated)  
**Last Updated:** October 13, 2025  
**Status:** Production Ready  
**Target:** Code Monkey Cybersecurity EOS Platform

---

## 🚨 CRITICAL: Storage Backend Decision

**As of Vault Enterprise 1.12.0, Vault will no longer start if configured with a storage backend other than Integrated Storage (Raft) or Consul.**

### Quick Decision Guide

```
┌─────────────────────────────────────────┐
│  What environment are you deploying?    │
└─────────────────┬───────────────────────┘
                  │
        ┌─────────┴─────────┐
        │                   │
        ▼                   ▼
┌──────────────┐    ┌──────────────┐
│ Development  │    │  Production  │
│   /Testing   │    │              │
└──────┬───────┘    └──────┬───────┘
       │                   │
       ▼                   ▼
┌──────────────┐    ┌──────────────┐
│ Single Node  │    │  5+ Nodes    │
│ Raft         │    │  Raft        │
│ Stored Keys  │    │  Auto-Unseal │
│ Manual       │    │  Autopilot   │
└──────────────┘    └──────────────┘

❌ File Storage: Development/Learning ONLY
  3-Node Raft: Small production (1 node failure tolerance)
✅ 5-Node Raft: Recommended production (2 node failure tolerance)
```

**For detailed decision guidance, see:** `eos-raft-decision-tree.md`

---

## Table of Contents

### Part 1: Quick Start Guides
- [Quick Start: Development (Single Node)](#quick-start-development)
- [Quick Start: Production (5-Node Cluster)](#quick-start-production)

### Part 2: Core Components
- [Storage Backends Comparison](#storage-backends)
- [Configuration Templates](#configuration-templates)
- [TLS Certificate Setup](#tls-setup)
- [Initialization and Unsealing](#initialization)

### Part 3: Production Deployment
- [Multi-Node Raft Cluster](#raft-cluster)
- [Autopilot Configuration](#autopilot)
- [Auto-Unseal Setup](#auto-unseal)
- [Load Balancer Configuration](#load-balancer)

### Part 4: Operations
- [Backup and Restore](#backup-restore)
- [Monitoring and Health Checks](#monitoring)
- [Migration from File to Raft](#migration)
- [Troubleshooting](#troubleshooting)

### Part 5: Reference
- [Complete Configuration Examples](#config-examples)
- [Port Reference](#port-reference)
- [Security Hardening Checklist](#security-hardening)
- [Implementation Checklist](#implementation-checklist)

---

## Part 1: Quick Start Guides

### Quick Start: Development (Single Node) {#quick-start-development}

**Use Case:** Local development, learning, POC  
**Time to Deploy:** 15-30 minutes  
**Prerequisites:** Ubuntu/Debian server with sudo access

#### Step 1: Install Vault
```bash
# Add HashiCorp repository
wget -O- https://apt.releases.hashicorp.com/gpg | \
  sudo gpg --dearmor -o /usr/share/keyrings/hashicorp-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
  https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \
  sudo tee /etc/apt/sources.list.d/hashicorp.list

sudo apt update && sudo apt install -y vault jq
```

#### Step 2: Create vault User
```bash
sudo useradd --system --no-create-home --shell /bin/false vault || true
```

#### Step 3: Create Directory Structure
```bash
sudo mkdir -p /opt/vault/{data,tls}
sudo mkdir -p /etc/vault.d
sudo chown -R vault:vault /opt/vault
sudo chmod 755 /opt/vault
```

#### Step 4: Generate Self-Signed Certificate
```bash
# Create certificate config
cat > /tmp/vault-cert-config.cnf <<'EOF'
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
C = AU
ST = WA
L = Fremantle
O = Code Monkey Cybersecurity
CN = localhost

[v3_req]
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.local
IP.1 = 127.0.0.1
EOF

# Generate certificate
sudo openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout /opt/vault/tls/vault-key.pem \
  -out /opt/vault/tls/vault-cert.pem \
  -config /tmp/vault-cert-config.cnf \
  -extensions v3_req

# Set permissions
sudo chown root:vault /opt/vault/tls/vault-key.pem
sudo chmod 640 /opt/vault/tls/vault-key.pem
sudo chown root:root /opt/vault/tls/vault-cert.pem
sudo chmod 644 /opt/vault/tls/vault-cert.pem
```

#### Step 5: Create Configuration
```bash
sudo tee /etc/vault.d/vault.hcl > /dev/null <<'EOF'
# Integrated Storage (Raft) - Single Node
storage "raft" {
  path    = "/opt/vault/data"
  node_id = "eos-vault-dev"
}

listener "tcp" {
  address         = "0.0.0.0:8179"
  cluster_address = "0.0.0.0:8180"
  tls_cert_file   = "/opt/vault/tls/vault-cert.pem"
  tls_key_file    = "/opt/vault/tls/vault-key.pem"
}

cluster_addr = "https://127.0.0.1:8180"
api_addr     = "https://127.0.0.1:8179"
disable_mlock = true
ui = true
EOF

sudo chown root:vault /etc/vault.d/vault.hcl
sudo chmod 640 /etc/vault.d/vault.hcl
```

#### Step 6: Create systemd Service
```bash
sudo tee /etc/systemd/system/vault.service > /dev/null <<'EOF'
[Unit]
Description=HashiCorp Vault
Documentation=https://developer.hashicorp.com/vault/docs
After=network-online.target
Wants=network-online.target
ConditionFileNotEmpty=/etc/vault.d/vault.hcl

[Service]
User=vault
Group=vault
Type=notify
EnvironmentFile=-/etc/vault.d/vault.env
ExecStart=/usr/bin/vault server -config=/etc/vault.d/vault.hcl
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
KillSignal=SIGINT
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
StartLimitInterval=60
StartLimitBurst=3
LimitNOFILE=65536
LimitMEMLOCK=infinity
AmbientCapabilities=CAP_IPC_LOCK
LimitCORE=0

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable vault
```

#### Step 7: Start and Initialize
```bash
# Start Vault
sudo systemctl start vault
sleep 5

# Check status
sudo systemctl status vault

# Set environment
export VAULT_ADDR='https://localhost:8179'
export VAULT_SKIP_VERIFY=1  # Only for self-signed certs

# Initialize
vault operator init -key-shares=5 -key-threshold=3 -format=json \
  > /tmp/vault_init.json

# Store securely
sudo mkdir -p /var/lib/eos/secret
sudo mv /tmp/vault_init.json /var/lib/eos/secret/
sudo chmod 600 /var/lib/eos/secret/vault_init.json

# Unseal
vault operator unseal $(jq -r '.unseal_keys_b64[0]' /var/lib/eos/secret/vault_init.json)
vault operator unseal $(jq -r '.unseal_keys_b64[1]' /var/lib/eos/secret/vault_init.json)
vault operator unseal $(jq -r '.unseal_keys_b64[2]' /var/lib/eos/secret/vault_init.json)

# Export root token
export VAULT_TOKEN=$(jq -r '.root_token' /var/lib/eos/secret/vault_init.json)

# Verify
vault status
vault operator raft list-peers
```

#### Step 8: Test
```bash
# Enable KV secrets engine
vault secrets enable -path=secret kv-v2

# Write test secret
vault kv put secret/test value="single-node-raft-test"

# Read test secret
vault kv get secret/test

# ✅ SUCCESS if you can read the secret
```

** SECURITY WARNING:** This stores all unseal keys in one file. This is ONLY acceptable for development. For production, see [Auto-Unseal Setup](#auto-unseal).

---

### Quick Start: Production (5-Node Cluster) {#quick-start-production}

**Use Case:** Production deployment with HA and failover  
**Time to Deploy:** 4-8 hours (includes testing)  
**Prerequisites:** 5 servers across 3 availability zones, cloud KMS (AWS/Azure/GCP)

**For comprehensive production deployment, see:**
- **Decision Guide:** `eos-raft-decision-tree.md`
- **Step-by-Step Checklist:** `eos-raft-implementation-checklist.md`
- **Technical Details:** `eos-raft-integration-guide.md`

#### High-Level Steps:

1. **Pre-Deployment Planning** (2-4 hours)
   - Determine node placement across AZs
   - Plan network topology
   - Set up cloud KMS for auto-unseal
   - Design backup strategy
   - Configure load balancer

2. **Infrastructure Setup** (1-2 hours)
   - Provision 5 servers
   - Configure networking and firewalls
   - Generate production TLS certificates
   - Set up monitoring infrastructure

3. **Vault Installation** (1-2 hours)
   - Install Vault on all nodes
   - Deploy configuration files
   - Configure auto-unseal
   - Set up systemd services

4. **Cluster Initialization** (1-2 hours)
   - Initialize first node
   - Join remaining nodes
   - Enable Autopilot
   - Configure load balancer health checks

5. **Operational Setup** (1-2 hours)
   - Configure automated backups
   - Set up monitoring and alerting
   - Test failover scenarios
   - Document procedures

**For detailed instructions, follow:** `eos-raft-implementation-checklist.md`

---

## Part 2: Core Components

### Storage Backends Comparison {#storage-backends}

#### Raft (Integrated Storage) - RECOMMENDED ✅

**HashiCorp Official Guidance:**
> "HashiCorp recommends using Vault's integrated storage for most use cases rather than configuring another system to store Vault data externally. Integrated Storage is an embedded Vault data storage available in Vault 1.4 or later."

**Use Cases:**
- ✅ Production deployments (REQUIRED for Enterprise 1.12.0+)
- ✅ High availability requirements
- ✅ Multi-node clusters
- ✅ Automatic failover needed
- ✅ No external dependencies desired

**Advantages:**
- Built-in HA and automatic failover
- No external dependencies (no Consul needed)
- Built-in snapshot/backup capabilities
- Automatic data replication
- Leader election built-in
- Supports Autopilot for node lifecycle management
- Performance optimized for Vault workloads

**Disadvantages:**
- More complex initial setup than file storage
- Requires TLS certificates with proper SANs
- Requires cluster planning (node count, AZ distribution)
- Requires understanding of Raft consensus algorithm

**Minimum Requirements:**
- 1 node (development only)
- 3 nodes (minimum HA, tolerates 1 node failure)
- 5 nodes (recommended production, tolerates 2 node failures)

**Configuration Example:**
```hcl
storage "raft" {
  path    = "/opt/vault/data"
  node_id = "eos-vault-node1"  # Must be unique per node
  
  # Production performance setting
  performance_multiplier = 1
  
  # Auto-join configuration (multi-node only)
  retry_join {
    leader_api_addr         = "https://node2.example.com:8179"
    leader_client_cert_file = "/opt/vault/tls/vault-cert.pem"
    leader_client_key_file  = "/opt/vault/tls/vault-key.pem"
    leader_ca_cert_file     = "/opt/vault/tls/vault-ca.pem"
    leader_tls_servername   = "node2.example.com"
  }
}
```

**For comprehensive Raft setup:** See `eos-raft-integration-guide.md`

---

#### File Storage - DEVELOPMENT ONLY 

**HashiCorp Official Guidance:**
> "The Filesystem storage backend stores Vault's data on the filesystem using a standard directory structure. It can be used for durable single server situations, or to develop locally where durability is not critical."

**CRITICAL LIMITATIONS:**
- ❌ No High Availability support
- ❌ No replication
- ❌ No automatic failover
- ❌ NOT SUPPORTED in Vault Enterprise 1.12.0+
- ❌ NOT RECOMMENDED for production by HashiCorp

**Use Cases:**
- ✅ Local development only
- ✅ Learning Vault concepts
- ✅ Proof-of-concept (non-production)

**Configuration Example:**
```hcl
#  DEVELOPMENT ONLY - NOT FOR PRODUCTION
storage "file" {
  path = "/opt/vault/data"
}
```

**Migration Path:**
If you currently use file storage, see [Migration from File to Raft](#migration).

---

### Configuration Templates {#configuration-templates}

#### Single-Node Raft (Development)

```hcl
# Vault Configuration - Single Node Raft (Development)
# File: /etc/vault.d/vault.hcl

storage "raft" {
  path    = "/opt/vault/data"
  node_id = "eos-vault-dev"
}

listener "tcp" {
  address         = "0.0.0.0:8179"
  cluster_address = "0.0.0.0:8180"
  tls_cert_file   = "/opt/vault/tls/vault-cert.pem"
  tls_key_file    = "/opt/vault/tls/vault-key.pem"
}

cluster_addr = "https://127.0.0.1:8180"
api_addr     = "https://127.0.0.1:8179"
disable_mlock = true
ui = true
```

#### Multi-Node Raft Node 1 (Production)

```hcl
# Vault Configuration - Node 1 (Leader-eligible)
# File: /etc/vault.d/vault.hcl

storage "raft" {
  path    = "/opt/vault/data"
  node_id = "eos-vault-node1-az1"
  
  # Production performance setting
  performance_multiplier = 1
  
  # Auto-join other nodes
  retry_join {
    leader_api_addr         = "https://eos-vault-node2.example.com:8179"
    leader_client_cert_file = "/opt/vault/tls/vault-cert.pem"
    leader_client_key_file  = "/opt/vault/tls/vault-key.pem"
    leader_ca_cert_file     = "/opt/vault/tls/vault-ca.pem"
    leader_tls_servername   = "eos-vault-node2"
  }
  
  retry_join {
    leader_api_addr         = "https://eos-vault-node3.example.com:8179"
    leader_client_cert_file = "/opt/vault/tls/vault-cert.pem"
    leader_client_key_file  = "/opt/vault/tls/vault-key.pem"
    leader_ca_cert_file     = "/opt/vault/tls/vault-ca.pem"
    leader_tls_servername   = "eos-vault-node3"
  }
  
  retry_join {
    leader_api_addr         = "https://eos-vault-node4.example.com:8179"
    leader_client_cert_file = "/opt/vault/tls/vault-cert.pem"
    leader_client_key_file  = "/opt/vault/tls/vault-key.pem"
    leader_ca_cert_file     = "/opt/vault/tls/vault-ca.pem"
    leader_tls_servername   = "eos-vault-node4"
  }
  
  retry_join {
    leader_api_addr         = "https://eos-vault-node5.example.com:8179"
    leader_client_cert_file = "/opt/vault/tls/vault-cert.pem"
    leader_client_key_file  = "/opt/vault/tls/vault-key.pem"
    leader_ca_cert_file     = "/opt/vault/tls/vault-ca.pem"
    leader_tls_servername   = "eos-vault-node5"
  }
}

listener "tcp" {
  address         = "0.0.0.0:8179"
  cluster_address = "0.0.0.0:8180"
  tls_cert_file   = "/opt/vault/tls/vault-cert.pem"
  tls_key_file    = "/opt/vault/tls/vault-key.pem"
  tls_min_version = "tls12"
}

# This node's addresses (CHANGE FOR EACH NODE)
cluster_addr = "https://10.0.1.10:8180"  # Node 1 IP
api_addr     = "https://10.0.1.10:8179"  # Node 1 IP

# Production hardening
disable_mlock = true  # Required for Raft
ui = true
log_level = "info"

# Telemetry for monitoring
telemetry {
  prometheus_retention_time = "30s"
  disable_hostname          = true
}

# Auto-unseal (AWS KMS example)
seal "awskms" {
  region     = "ap-southeast-2"
  kms_key_id = "alias/eos-vault-unseal"
}
```

**Important:** Each node (2-5) needs:
- Unique `node_id`
- Unique `cluster_addr` (its own IP)
- Unique `api_addr` (its own IP)
- Same `retry_join` blocks pointing to OTHER nodes

---

### TLS Certificate Setup {#tls-setup}

#### Critical Requirement for Raft

Raft clusters **require** TLS certificates with proper Subject Alternative Names (SANs). Each certificate must include:
- All node IP addresses
- All node hostnames/DNS names
- `localhost` and `127.0.0.1` (for local management)

#### Development Certificate (Self-Signed)

```bash
# Create certificate configuration
cat > vault-cert-config.cnf <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
C = AU
ST = WA
L = Fremantle
O = Code Monkey Cybersecurity
CN = eos-vault-node1

[v3_req]
keyUsage = keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
# Add ALL node hostnames
DNS.1 = eos-vault-node1
DNS.2 = eos-vault-node1.local
DNS.3 = eos-vault-node2
DNS.4 = eos-vault-node2.local
DNS.5 = eos-vault-node3
DNS.6 = eos-vault-node3.local
DNS.7 = eos-vault-node4
DNS.8 = eos-vault-node4.local
DNS.9 = eos-vault-node5
DNS.10 = eos-vault-node5.local
DNS.11 = localhost

# Add ALL node IPs
IP.1 = 127.0.0.1
IP.2 = 10.0.1.10  # Node 1
IP.3 = 10.0.1.11  # Node 2
IP.4 = 10.0.1.12  # Node 3
IP.5 = 10.0.1.13  # Node 4
IP.6 = 10.0.1.14  # Node 5
EOF

# Generate certificate (RSA 4096 for better security)
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout vault-key.pem \
  -out vault-cert.pem \
  -config vault-cert-config.cnf \
  -extensions v3_req

# Verify SANs
openssl x509 -in vault-cert.pem -text -noout | grep -A1 "Subject Alternative Name"

# Deploy to all nodes
for node in node1 node2 node3 node4 node5; do
  scp vault-cert.pem vault-key.pem $node:/tmp/
  ssh $node "sudo mv /tmp/vault-*.pem /opt/vault/tls/ && \
    sudo chown root:vault /opt/vault/tls/vault-key.pem && \
    sudo chmod 640 /opt/vault/tls/vault-key.pem && \
    sudo chown root:root /opt/vault/tls/vault-cert.pem && \
    sudo chmod 644 /opt/vault/tls/vault-cert.pem"
done
```

#### Production Certificate (Let's Encrypt or Internal CA)

For production, use:
- **Let's Encrypt** for publicly accessible clusters
- **Internal PKI/CA** for private clusters
- **Commercial CA** for regulated industries

**Let's Encrypt Example:**
```bash
# Install certbot
sudo apt install -y certbot

# Generate certificate (DNS challenge for wildcard)
sudo certbot certonly --dns-route53 \
  -d "*.eos-vault.example.com" \
  -d "eos-vault.example.com" \
  --preferred-challenges dns

# Certificates will be in:
# /etc/letsencrypt/live/eos-vault.example.com/fullchain.pem
# /etc/letsencrypt/live/eos-vault.example.com/privkey.pem

# Deploy to Vault
sudo cp /etc/letsencrypt/live/eos-vault.example.com/fullchain.pem \
  /opt/vault/tls/vault-cert.pem
sudo cp /etc/letsencrypt/live/eos-vault.example.com/privkey.pem \
  /opt/vault/tls/vault-key.pem

# Set permissions
sudo chown root:vault /opt/vault/tls/vault-key.pem
sudo chmod 640 /opt/vault/tls/vault-key.pem
sudo chown root:root /opt/vault/tls/vault-cert.pem
sudo chmod 644 /opt/vault/tls/vault-cert.pem
```

**Auto-renewal setup:**
```bash
# Add renewal hook
sudo tee /etc/letsencrypt/renewal-hooks/post/reload-vault.sh > /dev/null <<'EOF'
#!/bin/bash
# Copy renewed certs to Vault
cp /etc/letsencrypt/live/eos-vault.example.com/fullchain.pem \
  /opt/vault/tls/vault-cert.pem
cp /etc/letsencrypt/live/eos-vault.example.com/privkey.pem \
  /opt/vault/tls/vault-key.pem

# Set permissions
chown root:vault /opt/vault/tls/vault-key.pem
chmod 640 /opt/vault/tls/vault-key.pem
chown root:root /opt/vault/tls/vault-cert.pem
chmod 644 /opt/vault/tls/vault-cert.pem

# Reload Vault (not restart - this is graceful)
systemctl reload vault
EOF

sudo chmod +x /etc/letsencrypt/renewal-hooks/post/reload-vault.sh
```

---

### Initialization and Unsealing {#initialization}

#### Single-Node Initialization

```bash
# Set environment
export VAULT_ADDR='https://localhost:8179'
export VAULT_SKIP_VERIFY=1  # Only for self-signed certs

# Initialize Vault
vault operator init \
  -key-shares=5 \
  -key-threshold=3 \
  -format=json > /tmp/vault_init.json

# Store securely
sudo mkdir -p /var/lib/eos/secret
sudo mv /tmp/vault_init.json /var/lib/eos/secret/
sudo chmod 600 /var/lib/eos/secret/vault_init.json

# Unseal (need 3 of 5 keys)
vault operator unseal $(jq -r '.unseal_keys_b64[0]' /var/lib/eos/secret/vault_init.json)
vault operator unseal $(jq -r '.unseal_keys_b64[1]' /var/lib/eos/secret/vault_init.json)
vault operator unseal $(jq -r '.unseal_keys_b64[2]' /var/lib/eos/secret/vault_init.json)

# Set root token
export VAULT_TOKEN=$(jq -r '.root_token' /var/lib/eos/secret/vault_init.json)

# Verify
vault status
vault operator raft list-peers

# Expected output:
# Node                    Address              State     Voter
# ----                    -------              -----     -----
# eos-vault-dev           127.0.0.1:8180       leader    true
```

**🚨 SECURITY WARNING:** Storing all 5 unseal keys in one file defeats Shamir's Secret Sharing. This is ONLY acceptable for development environments.

**For Production, use:**
1. **Distributed keys:** Give each key to a different person/team
2. **Auto-unseal:** Use cloud KMS (AWS/Azure/GCP) - see [Auto-Unseal Setup](#auto-unseal)
3. **HSM:** Hardware Security Module (Enterprise only)

---

#### Multi-Node Cluster Initialization

```bash
# STEP 1: Initialize first node (will become initial leader)
# On node1:
export VAULT_ADDR='https://node1.example.com:8179'
vault operator init -format=json > vault_init.json

# If using manual unsealing:
vault operator unseal $(jq -r '.unseal_keys_b64[0]' vault_init.json)
vault operator unseal $(jq -r '.unseal_keys_b64[1]' vault_init.json)
vault operator unseal $(jq -r '.unseal_keys_b64[2]' vault_init.json)

# Set root token
export VAULT_TOKEN=$(jq -r '.root_token' vault_init.json)

# Verify node1 is leader
vault operator raft list-peers

# STEP 2: Join node2 to cluster
# On node2:
export VAULT_ADDR='https://node2.example.com:8179'
vault operator raft join https://node1.example.com:8179

# Unseal node2 (using SAME keys from node1)
vault operator unseal $(jq -r '.unseal_keys_b64[0]' /path/to/vault_init.json)
vault operator unseal $(jq -r '.unseal_keys_b64[1]' /path/to/vault_init.json)
vault operator unseal $(jq -r '.unseal_keys_b64[2]' /path/to/vault_init.json)

# STEP 3: Repeat for nodes 3, 4, 5
# On each node:
#   1. Join cluster: vault operator raft join https://node1.example.com:8179
#   2. Unseal with same keys
#   3. Verify: vault status

# STEP 4: Verify cluster formation
# On node1:
export VAULT_ADDR='https://node1.example.com:8179'
export VAULT_TOKEN=$(jq -r '.root_token' vault_init.json)
vault operator raft list-peers

# Expected output:
# Node                    Address              State       Voter
# ----                    -------              -----       -----
# eos-vault-node1-az1     10.0.1.10:8180      leader      true
# eos-vault-node2-az2     10.0.1.11:8180      follower    true
# eos-vault-node3-az2     10.0.1.12:8180      follower    true
# eos-vault-node4-az3     10.0.1.13:8180      follower    true
# eos-vault-node5-az3     10.0.1.14:8180      follower    true
```

**Note:** If using auto-unseal, nodes unseal automatically after initialization/joining.

---

## Part 3: Production Deployment

### Multi-Node Raft Cluster {#raft-cluster}

#### Recommended Topology: 5 Nodes Across 3 AZs

```
AZ1 (us-west-2a):
  - Node 1 (10.0.1.10)
  - Node 2 (10.0.1.11)

AZ2 (us-west-2b):
  - Node 3 (10.0.1.12)
  - Node 4 (10.0.1.13)

AZ3 (us-west-2c):
  - Node 5 (10.0.1.14)

Failure Tolerance:
  - Can lose entire AZ1 or AZ2 (2 nodes)
  - Can lose any 2 individual nodes
  - Quorum: 3 nodes minimum
```

#### Why 5 Nodes?

From HashiCorp's official guidance:
> "For production deployments, HashiCorp recommends at least 5 servers to maintain a minimum failure tolerance of 2."

**Quorum Math:**
- 3 nodes = Quorum of 2 (tolerates 1 failure)
- 5 nodes = Quorum of 3 (tolerates 2 failures) ✅
- 7 nodes = Quorum of 4 (tolerates 3 failures, but diminishing returns)

**Cost-Benefit Analysis:**
- 3 nodes: Minimal HA, single AZ failure = outage
- 5 nodes: Optimal balance, can lose entire AZ
- 7 nodes: Expensive, same AZ tolerance as 5 nodes

**For detailed cluster planning:** See `eos-raft-decision-tree.md`

---

### Autopilot Configuration {#autopilot}

Autopilot automates operational tasks like:
- Removing dead servers from the cluster
- Promoting healthy non-voter nodes to voters
- Managing node lifecycle

**Enable Autopilot (after cluster initialization):**
```bash
export VAULT_ADDR='https://node1.example.com:8179'
export VAULT_TOKEN='<root_token>'

# Configure Autopilot
vault operator raft autopilot set-config \
  -cleanup-dead-servers=true \
  -dead-server-last-contact-threshold=10m \
  -min-quorum=3 \
  -server-stabilization-time=10s

# Verify configuration
vault operator raft autopilot get-config

# Check autopilot state
vault operator raft autopilot state
```

**Configuration Explanation:**
- `cleanup-dead-servers=true`: Automatically remove failed nodes
- `dead-server-last-contact-threshold=10m`: Consider node dead after 10min
- `min-quorum=3`: Maintain minimum 3 voting nodes (for 5-node cluster)
- `server-stabilization-time=10s`: Wait 10s before promoting new nodes

---

### Auto-Unseal Setup {#auto-unseal}

Manual unsealing in production is operationally burdensome. After a restart, EVERY node must be manually unsealed with 3 of 5 keys.

**Auto-unseal solves this by using:**
- Cloud KMS (AWS, Azure, GCP)
- Hardware Security Module (HSM)
- Transit secrets engine (another Vault cluster)

#### AWS KMS Auto-Unseal

**Prerequisites:**
1. AWS account with KMS access
2. KMS key created
3. IAM role for Vault EC2 instances

**Create KMS Key:**
```bash
# Using AWS CLI
aws kms create-key \
  --description "EOS Vault Auto-Unseal Key" \
  --key-usage ENCRYPT_DECRYPT \
  --region ap-southeast-2

# Create alias
aws kms create-alias \
  --alias-name alias/eos-vault-unseal \
  --target-key-id <key-id-from-above> \
  --region ap-southeast-2
```

**Create IAM Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:Encrypt",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:ap-southeast-2:ACCOUNT_ID:key/*"
    }
  ]
}
```

**Add to Vault Configuration:**
```hcl
seal "awskms" {
  region     = "ap-southeast-2"
  kms_key_id = "alias/eos-vault-unseal"
}
```

**Migration from Manual to Auto-Unseal:**
```bash
# 1. Update configuration on all nodes to add seal "awskms" block
# 2. Restart Vault services one by one
# 3. On first restart, Vault will detect the transition
# 4. Unseal once manually, then auto-unseal takes over
# 5. Original unseal keys become "recovery keys" (store securely!)
```

---

#### Azure Key Vault Auto-Unseal

**Prerequisites:**
1. Azure subscription
2. Key Vault instance created
3. Key in Key Vault
4. Service principal with access

**Create Azure Resources:**
```bash
# Create resource group
az group create --name eos-vault-rg --location australiaeast

# Create Key Vault
az keyvault create \
  --name eos-vault-unseal \
  --resource-group eos-vault-rg \
  --location australiaeast

# Create key
az keyvault key create \
  --vault-name eos-vault-unseal \
  --name eos-vault-key \
  --protection software

# Create service principal
az ad sp create-for-rbac \
  --name eos-vault-sp \
  --skip-assignment

# Grant permissions
az keyvault set-policy \
  --name eos-vault-unseal \
  --spn <service-principal-app-id> \
  --key-permissions get unwrapKey wrapKey
```

**Add to Vault Configuration:**
```hcl
seal "azurekeyvault" {
  tenant_id      = "<azure-tenant-id>"
  client_id      = "<service-principal-app-id>"
  client_secret  = "<service-principal-password>"
  vault_name     = "eos-vault-unseal"
  key_name       = "eos-vault-key"
}
```

---

#### GCP Cloud KMS Auto-Unseal

**Prerequisites:**
1. GCP project
2. Cloud KMS API enabled
3. KMS keyring and key created
4. Service account with permissions

**Create GCP Resources:**
```bash
# Enable Cloud KMS API
gcloud services enable cloudkms.googleapis.com

# Create keyring
gcloud kms keyrings create eos-vault-keyring \
  --location australia-southeast1

# Create key
gcloud kms keys create eos-vault-key \
  --location australia-southeast1 \
  --keyring eos-vault-keyring \
  --purpose encryption

# Create service account
gcloud iam service-accounts create eos-vault-sa \
  --display-name "EOS Vault Auto-Unseal"

# Grant permissions
gcloud kms keys add-iam-policy-binding eos-vault-key \
  --location australia-southeast1 \
  --keyring eos-vault-keyring \
  --member serviceAccount:eos-vault-sa@PROJECT_ID.iam.gserviceaccount.com \
  --role roles/cloudkms.cryptoKeyEncrypterDecrypter
```

**Add to Vault Configuration:**
```hcl
seal "gcpckms" {
  project     = "eos-vault-project"
  region      = "australia-southeast1"
  key_ring    = "eos-vault-keyring"
  crypto_key  = "eos-vault-key"
  
  # Use Application Default Credentials or specify credentials file
  credentials = "/opt/vault/gcp-credentials.json"
}
```

---

### Load Balancer Configuration {#load-balancer}

Load balancers distribute traffic across Vault nodes and provide:
- Single entry point for clients
- Automatic failover (no client-side leader detection needed)
- SSL termination (optional)
- Health checking

#### AWS Application Load Balancer (ALB)

```bash
# Create target group
aws elbv2 create-target-group \
  --name eos-vault-tg \
  --protocol HTTPS \
  --port 8179 \
  --vpc-id <vpc-id> \
  --health-check-protocol HTTPS \
  --health-check-path /v1/sys/health \
  --health-check-interval-seconds 10 \
  --health-check-timeout-seconds 5 \
  --healthy-threshold-count 2 \
  --unhealthy-threshold-count 2 \
  --matcher HttpCode=200,429

# Register targets
aws elbv2 register-targets \
  --target-group-arn <tg-arn> \
  --targets Id=<node1-instance-id> Id=<node2-instance-id> \
    Id=<node3-instance-id> Id=<node4-instance-id> Id=<node5-instance-id>

# Create load balancer
aws elbv2 create-load-balancer \
  --name eos-vault-lb \
  --subnets <subnet-1> <subnet-2> <subnet-3> \
  --security-groups <sg-id> \
  --scheme internal \
  --type application

# Create listener
aws elbv2 create-listener \
  --load-balancer-arn <lb-arn> \
  --protocol HTTPS \
  --port 8179 \
  --certificates CertificateArn=<acm-cert-arn> \
  --default-actions Type=forward,TargetGroupArn=<tg-arn>
```

**Critical:** Health check must accept both:
- `200` - Leader node (active)
- `429` - Follower node (standby, but healthy)

---

#### HAProxy Configuration

```haproxy
# /etc/haproxy/haproxy.cfg

global
    log /dev/log local0
    chroot /var/lib/haproxy
    stats socket /run/haproxy/admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon

defaults
    log     global
    mode    http
    option  httplog
    option  dontlognull
    timeout connect 5000
    timeout client  50000
    timeout server  50000

frontend vault_frontend
    bind *:8179 ssl crt /etc/haproxy/certs/vault.pem
    default_backend vault_backend

backend vault_backend
    balance roundrobin
    option httpchk GET /v1/sys/health
    http-check expect status 200,429,473  # 200=leader, 429=standby, 473=perf-standby
    
    server vault1 10.0.1.10:8179 check ssl verify none
    server vault2 10.0.1.11:8179 check ssl verify none
    server vault3 10.0.1.12:8179 check ssl verify none
    server vault4 10.0.1.13:8179 check ssl verify none
    server vault5 10.0.1.14:8179 check ssl verify none

listen stats
    bind *:8404
    stats enable
    stats uri /stats
    stats refresh 5s
```

**Deploy HAProxy:**
```bash
# Install
sudo apt install -y haproxy

# Copy configuration
sudo cp haproxy.cfg /etc/haproxy/haproxy.cfg

# Validate configuration
sudo haproxy -c -f /etc/haproxy/haproxy.cfg

# Restart
sudo systemctl restart haproxy
sudo systemctl status haproxy

# Test health endpoint
curl http://localhost:8404/stats
```

---

#### NGINX Configuration

```nginx
# /etc/nginx/conf.d/vault.conf

upstream vault_cluster {
    least_conn;  # Route to node with least connections
    
    server 10.0.1.10:8179 max_fails=3 fail_timeout=30s;
    server 10.0.1.11:8179 max_fails=3 fail_timeout=30s;
    server 10.0.1.12:8179 max_fails=3 fail_timeout=30s;
    server 10.0.1.13:8179 max_fails=3 fail_timeout=30s;
    server 10.0.1.14:8179 max_fails=3 fail_timeout=30s;
}

server {
    listen 8179 ssl http2;
    server_name vault.example.com;
    
    ssl_certificate /etc/nginx/ssl/vault-cert.pem;
    ssl_certificate_key /etc/nginx/ssl/vault-key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    location / {
        proxy_pass https://vault_cluster;
        proxy_ssl_verify off;  # If using self-signed certs on backend
        
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        proxy_read_timeout 90;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
    }
    
    # Health check endpoint (optional)
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
```

---

## Part 4: Operations

### Backup and Restore {#backup-restore}

**Critical from HashiCorp:**
> "Vault snapshots are the only supported method for backing up Vault with Integrated Storage. Restoring from disparate disk backups can introduce data consistency errors and should never be attempted."

#### Manual Snapshots

```bash
# Take snapshot
export VAULT_ADDR='https://localhost:8179'
export VAULT_TOKEN='<token-with-snapshot-permission>'

vault operator raft snapshot save backup-$(date +%Y%m%d-%H%M%S).snap

# Verify snapshot integrity
vault operator raft snapshot inspect backup-20251013-120000.snap

# Example output:
# ID: 2-1234567-1234567890
# Size: 1.2 MB
# Index: 1234567
# Term: 2
# Version: 1
```

#### Automated Snapshots (Script)

```bash
#!/bin/bash
# /usr/local/bin/vault-backup.sh

set -euo pipefail

# Configuration
VAULT_ADDR="${VAULT_ADDR:-https://localhost:8179}"
BACKUP_DIR="${BACKUP_DIR:-/opt/vault/backups}"
RETENTION_DAYS="${RETENTION_DAYS:-7}"
S3_BUCKET="${S3_BUCKET:-}"  # Optional: Upload to S3

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

# Generate filename
DATE=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="$BACKUP_DIR/vault-snapshot-$DATE.snap"

# Take snapshot
echo "Taking Vault snapshot..."
vault operator raft snapshot save "$BACKUP_FILE"

# Verify snapshot
echo "Verifying snapshot integrity..."
if vault operator raft snapshot inspect "$BACKUP_FILE" > /dev/null; then
    echo "✅ Snapshot verified: $BACKUP_FILE"
else
    echo "❌ ERROR: Snapshot verification failed"
    exit 1
fi

# Upload to S3 (if configured)
if [ -n "$S3_BUCKET" ]; then
    echo "Uploading to S3..."
    aws s3 cp "$BACKUP_FILE" "s3://$S3_BUCKET/vault-backups/"
    echo "✅ Uploaded to S3"
fi

# Cleanup old backups
echo "Cleaning up old backups (retention: $RETENTION_DAYS days)..."
find "$BACKUP_DIR" -name "vault-snapshot-*.snap" -mtime +"$RETENTION_DAYS" -delete

echo "✅ Backup complete: $BACKUP_FILE"
```

**Schedule with Cron:**
```bash
# Edit crontab
sudo crontab -e

# Add daily backup at 2 AM
0 2 * * * /usr/local/bin/vault-backup.sh >> /var/log/vault-backup.log 2>&1
```

**Make script executable:**
```bash
sudo chmod +x /usr/local/bin/vault-backup.sh

# Test manually
sudo /usr/local/bin/vault-backup.sh
```

---

#### Automated Snapshots (Vault Enterprise)

Vault Enterprise has built-in automated snapshot functionality:

```bash
# Configure daily snapshots to S3
vault write sys/storage/raft/snapshot-auto/config/daily \
  interval="24h" \
  retain=30 \
  storage_type="aws-s3" \
  aws_s3_bucket="eos-vault-backups" \
  aws_s3_region="ap-southeast-2" \
  aws_s3_endpoint="https://s3.ap-southeast-2.amazonaws.com"

# Configure hourly snapshots to local storage
vault write sys/storage/raft/snapshot-auto/config/hourly \
  interval="1h" \
  retain=24 \
  storage_type="local" \
  path_prefix="/opt/vault/backups/hourly" \
  local_max_space=10737418240  # 10GB

# List configured snapshots
vault list sys/storage/raft/snapshot-auto/config

# Check snapshot status
vault read sys/storage/raft/snapshot-auto/status/daily
```

---

#### Restore from Snapshot

** WARNING:** Restoring will overwrite current data. Always take a current snapshot before restoring.

```bash
# STEP 1: Take a "before restore" snapshot (safety net)
vault operator raft snapshot save before-restore-$(date +%Y%m%d-%H%M%S).snap

# STEP 2: Stop all Vault nodes except one
# On nodes 2-5:
sudo systemctl stop vault

# STEP 3: Restore snapshot on remaining node
# On node1:
export VAULT_ADDR='https://node1.example.com:8179'
export VAULT_TOKEN='<root_token>'

vault operator raft snapshot restore -force backup-20251013-120000.snap

# STEP 4: Wait for restore to complete (check logs)
sudo journalctl -u vault -f

# STEP 5: Restart all other nodes
# On nodes 2-5:
sudo systemctl start vault

# STEP 6: Unseal all nodes (if manual unsealing)
# On each node:
vault operator unseal <key1>
vault operator unseal <key2>
vault operator unseal <key3>

# STEP 7: Verify cluster reformed
vault operator raft list-peers
vault status

# STEP 8: Verify data
vault kv list secret/
vault kv get secret/test
```

---

### Monitoring and Health Checks {#monitoring}

#### Health Endpoint

```bash
# Check health
curl -k https://localhost:8179/v1/sys/health

# Response codes:
# 200 - Initialized, unsealed, active (leader)
# 429 - Unsealed, standby (follower)
# 472 - Disaster recovery mode
# 473 - Performance standby
# 501 - Not initialized
# 503 - Sealed
```

**JSON Response Example (Leader):**
```json
{
  "initialized": true,
  "sealed": false,
  "standby": false,
  "performance_standby": false,
  "replication_performance_mode": "disabled",
  "replication_dr_mode": "disabled",
  "server_time_utc": 1697200000,
  "version": "1.20.4",
  "cluster_name": "eos-vault-cluster",
  "cluster_id": "abc123..."
}
```

---

#### Prometheus Metrics

**Enable telemetry in vault.hcl:**
```hcl
telemetry {
  prometheus_retention_time = "30s"
  disable_hostname          = true
}
```

**Prometheus scrape configuration:**
```yaml
# /etc/prometheus/prometheus.yml

scrape_configs:
  - job_name: 'vault'
    metrics_path: '/v1/sys/metrics'
    params:
      format: ['prometheus']
    scheme: https
    tls_config:
      insecure_skip_verify: true  # If using self-signed certs
    static_configs:
      - targets:
        - 'node1.example.com:8179'
        - 'node2.example.com:8179'
        - 'node3.example.com:8179'
        - 'node4.example.com:8179'
        - 'node5.example.com:8179'
```

**Key metrics to monitor:**
- `vault_core_unsealed` - 0 = sealed, 1 = unsealed
- `vault_raft_leader` - 0 = follower, 1 = leader
- `vault_raft_peers` - Number of cluster nodes
- `vault_raft_apply` - Log replication rate
- `vault_raft_commitTime` - Consensus latency (should be <100ms)
- `vault_raft_leader_lastContact` - Time since last follower contact

---

#### Grafana Dashboard

Import official HashiCorp Vault dashboard:
- Dashboard ID: **12904**
- URL: https://grafana.com/grafana/dashboards/12904

Or create custom dashboard with panels for:
1. Cluster Overview (nodes, leader, quorum status)
2. Request Rates (reads, writes, errors)
3. Performance (latency, throughput)
4. Raft Metrics (replication lag, commits/sec)
5. Audit Activity (authentications, secret access)

---

#### Alert Rules

**Prometheus alert rules** (`/etc/prometheus/rules/vault.yml`):
```yaml
groups:
  - name: vault
    interval: 30s
    rules:
      - alert: VaultDown
        expr: up{job="vault"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Vault instance {{ $labels.instance }} is down"
          description: "Vault has been down for more than 5 minutes."
          
      - alert: VaultSealed
        expr: vault_core_unsealed == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Vault instance {{ $labels.instance }} is sealed"
          description: "Vault is sealed and cannot serve requests."
          
      - alert: VaultNoLeader
        expr: sum(vault_raft_leader) == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "No Raft leader elected"
          description: "Vault cluster has no leader, unable to process writes."
          
      - alert: VaultQuorumLoss
        expr: vault_raft_peers < 3
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Vault cluster below minimum quorum"
          description: "Cluster has {{ $value }} nodes, need 3+ for quorum."
          
      - alert: VaultHighLatency
        expr: vault_raft_commitTime > 100
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Vault Raft commit latency high"
          description: "Raft commit latency is {{ $value }}ms (>100ms)."
          
      - alert: VaultLeaderChanges
        expr: increase(vault_raft_leader[1h]) > 3
        labels:
          severity: warning
        annotations:
          summary: "Multiple leader changes detected"
          description: "Vault cluster has had {{ $value }} leader changes in 1 hour."
```

---

### Migration from File to Raft {#migration}

** CRITICAL:** You cannot convert file storage to Raft in-place. This requires a data migration with downtime.

#### Migration Process Overview

1. **Export all data from file-based Vault**
2. **Stop old Vault**
3. **Install new Raft-based Vault**
4. **Initialize new Vault**
5. **Import all data**

#### Detailed Migration Steps

```bash
# PHASE 1: PREPARATION (Do not proceed until complete)

# 1.1: Export all secrets
export VAULT_ADDR='https://localhost:8179'
export VAULT_TOKEN='<root_token>'

# Create migration directory
mkdir -p /tmp/vault-migration
cd /tmp/vault-migration

# Export all KV secrets recursively
vault kv list -format=json secret/ | jq -r '.[]' | while read path; do
  echo "Exporting: secret/$path"
  vault kv get -format=json "secret/$path" > "secret-${path/\//-}.json"
done

# 1.2: Export all policies
vault policy list | while read policy; do
  echo "Exporting policy: $policy"
  vault policy read "$policy" > "policy-$policy.hcl"
done

# 1.3: Export auth methods configuration
vault auth list -format=json > auth-methods.json

# 1.4: Export audit devices
vault audit list -format=json > audit-devices.json

# 1.5: Take final backup
vault operator raft snapshot save final-file-backup.snap 2>/dev/null || \
  tar -czf final-file-backup.tar.gz /opt/vault/data

# 1.6: Verify all exports
ls -lh /tmp/vault-migration
# Should see all exported files

# PHASE 2: TRANSITION

# 2.1: Schedule maintenance window (announce to users)

# 2.2: Stop Vault
sudo systemctl stop vault

# 2.3: Backup current installation
sudo cp -r /opt/vault /opt/vault.file-backup
sudo cp -r /etc/vault.d /etc/vault.d.file-backup

# 2.4: Clear data directory
sudo rm -rf /opt/vault/data/*

# 2.5: Update configuration to Raft
sudo tee /etc/vault.d/vault.hcl > /dev/null <<'EOF'
storage "raft" {
  path    = "/opt/vault/data"
  node_id = "eos-vault-node1"
}

listener "tcp" {
  address         = "0.0.0.0:8179"
  cluster_address = "0.0.0.0:8180"
  tls_cert_file   = "/opt/vault/tls/vault-cert.pem"
  tls_key_file    = "/opt/vault/tls/vault-key.pem"
}

cluster_addr = "https://127.0.0.1:8180"
api_addr     = "https://127.0.0.1:8179"
disable_mlock = true
ui = true
EOF

# 2.6: Start Vault with Raft
sudo systemctl start vault

# 2.7: Initialize new Vault
export VAULT_ADDR='https://localhost:8179'
vault operator init -format=json > vault_init_raft.json

# 2.8: Unseal
vault operator unseal $(jq -r '.unseal_keys_b64[0]' vault_init_raft.json)
vault operator unseal $(jq -r '.unseal_keys_b64[1]' vault_init_raft.json)
vault operator unseal $(jq -r '.unseal_keys_b64[2]' vault_init_raft.json)

# 2.9: Set root token
export VAULT_TOKEN=$(jq -r '.root_token' vault_init_raft.json)

# PHASE 3: DATA IMPORT

# 3.1: Re-enable secrets engines
vault secrets enable -path=secret kv-v2

# 3.2: Import secrets
cd /tmp/vault-migration
for file in secret-*.json; do
  path=${file#secret-}
  path=${path%.json}
  path=${path//-/\/}
  echo "Importing: secret/$path"
  
  # Extract data from JSON
  data=$(jq -r '.data.data | to_entries | map("\(.key)=\(.value)") | join(" ")' "$file")
  
  # Import (construct vault kv put command)
  eval "vault kv put secret/$path $data"
done

# 3.3: Import policies
for file in policy-*.hcl; do
  policy=${file#policy-}
  policy=${policy%.hcl}
  echo "Importing policy: $policy"
  vault policy write "$policy" "$file"
done

# 3.4: Re-configure auth methods
# (This is manual based on your auth-methods.json)
# Example for userpass:
vault auth enable userpass
vault write auth/userpass/users/admin password="..." policies="admin"

# 3.5: Re-configure audit devices
# (Based on your audit-devices.json)
# Example:
vault audit enable file file_path=/var/log/vault/audit.log

# PHASE 4: VERIFICATION

# 4.1: Verify secrets accessible
vault kv list secret/
vault kv get secret/test

# 4.2: Verify policies
vault policy list

# 4.3: Test authentication
vault login -method=userpass username=admin

# 4.4: Verify Raft status
vault operator raft list-peers

# 4.5: Take snapshot of new Raft-based Vault
vault operator raft snapshot save post-migration-verification.snap

# PHASE 5: CLEANUP (After 1-2 weeks of successful operation)

# 5.1: Archive old backups
sudo tar -czf /backup/vault-file-storage-archive-$(date +%Y%m%d).tar.gz \
  /opt/vault.file-backup \
  /etc/vault.d.file-backup \
  /tmp/vault-migration

# 5.2: Move archive to long-term storage
# (S3, tape, etc.)

# 5.3: Remove old files (only after confirming archive)
# sudo rm -rf /opt/vault.file-backup
# sudo rm -rf /etc/vault.d.file-backup
# sudo rm -rf /tmp/vault-migration
```

**Estimated Downtime:**
- Small Vault (<100 secrets): 15-30 minutes
- Medium Vault (<1000 secrets): 1-2 hours
- Large Vault (>1000 secrets): 2-4 hours

**Rollback Plan:**
If migration fails:
```bash
# Stop new Vault
sudo systemctl stop vault

# Restore old configuration
sudo rm -rf /opt/vault/data
sudo cp -r /opt/vault.file-backup/* /opt/vault/
sudo cp -r /etc/vault.d.file-backup/* /etc/vault.d/

# Start old Vault
sudo systemctl start vault
```

---

### Troubleshooting {#troubleshooting}

#### Cluster Won't Form

**Symptoms:**
- Nodes don't appear in `vault operator raft list-peers`
- Logs show connection errors

**Checks:**
```bash
# 1. Verify network connectivity
nc -zv node2.example.com 8179
nc -zv node2.example.com 8180

# 2. Check firewall rules
sudo ufw status
# Should allow ports 8179 and 8180

# 3. Verify TLS certificates have correct SANs
openssl x509 -in /opt/vault/tls/vault-cert.pem -text -noout | \
  grep -A1 "Subject Alternative Name"

# 4. Check Vault service status
sudo systemctl status vault
sudo journalctl -u vault -n 100

# 5. Verify configuration
vault operator validate /etc/vault.d/vault.hcl

# 6. Check retry_join targets
grep -A5 "retry_join" /etc/vault.d/vault.hcl
```

**Common Fixes:**
- Ensure all node IPs/hostnames in certificate SANs
- Verify `leader_tls_servername` matches certificate CN or SAN
- Check `cluster_addr` and `api_addr` use correct IPs for each node
- Ensure `node_id` is unique per node

---

#### Node Won't Join Cluster

**Symptoms:**
- `vault operator raft join` fails
- Error: "failed to join raft cluster"

**Checks:**
```bash
# 1. Can reach leader node?
curl -k https://leader.example.com:8179/v1/sys/health

# 2. Is leader unsealed?
export VAULT_ADDR='https://leader.example.com:8179'
vault status

# 3. Are credentials correct?
# Verify TLS cert/key paths in retry_join blocks

# 4. Check logs on leader
# On leader node:
sudo journalctl -u vault -f

# 5. Check logs on joining node
# On joining node:
sudo journalctl -u vault -f
```

**Common Fixes:**
- Leader must be unsealed before joins
- TLS certificate must be valid for leader hostname
- Ensure `retry_join` has correct paths to certs

---

#### Cluster Loses Quorum

**Symptoms:**
- Vault returns 503 errors
- Cannot elect leader
- `vault status` shows error

**Recovery:**
```bash
# Check how many nodes are up
vault operator raft list-peers

# If less than quorum (3 for 5-node cluster):
# OPTION 1: Bring failed nodes back online
# On failed nodes:
sudo systemctl start vault
vault operator unseal <keys>

# OPTION 2: Remove failed nodes (if unrecoverable)
# On remaining node with quorum:
vault operator raft remove-peer <failed-node-id>

# OPTION 3: Restore from snapshot (last resort)
vault operator raft snapshot restore latest-backup.snap
```

---

#### High Raft Commit Latency

**Symptoms:**
- Writes are slow
- `vault_raft_commitTime` metric >100ms

**Checks:**
```bash
# 1. Check disk I/O performance
sudo iostat -x 1

# 2. Check network latency between nodes
ping -c 10 node2.example.com

# 3. Check Vault logs for issues
sudo journalctl -u vault | grep -i "slow\|latency\|timeout"

# 4. Check Raft metrics
curl -k https://localhost:8179/v1/sys/metrics?format=prometheus | \
  grep vault_raft
```

**Common Fixes:**
- Use SSDs for `/opt/vault/data`
- Reduce network latency (place nodes closer)
- Tune `performance_multiplier` (lower = faster, but more resource usage)
- Check for disk space issues

---

## Part 5: Reference

### Complete Configuration Examples {#config-examples}

#### Production 5-Node Cluster - Node 1

```hcl
# /etc/vault.d/vault.hcl - Node 1 (eos-vault-node1-az1)

# Integrated Storage (Raft)
storage "raft" {
  path    = "/opt/vault/data"
  node_id = "eos-vault-node1-az1"
  
  # Production performance
  performance_multiplier = 1
  
  # Auto-join other nodes in cluster
  retry_join {
    leader_api_addr         = "https://eos-vault-node2-az2.eos.local:8179"
    leader_client_cert_file = "/opt/vault/tls/vault-cert.pem"
    leader_client_key_file  = "/opt/vault/tls/vault-key.pem"
    leader_ca_cert_file     = "/opt/vault/tls/vault-ca.pem"
    leader_tls_servername   = "eos-vault-node2-az2"
  }
  
  retry_join {
    leader_api_addr         = "https://eos-vault-node3-az2.eos.local:8179"
    leader_client_cert_file = "/opt/vault/tls/vault-cert.pem"
    leader_client_key_file  = "/opt/vault/tls/vault-key.pem"
    leader_ca_cert_file     = "/opt/vault/tls/vault-ca.pem"
    leader_tls_servername   = "eos-vault-node3-az2"
  }
  
  retry_join {
    leader_api_addr         = "https://eos-vault-node4-az3.eos.local:8179"
    leader_client_cert_file = "/opt/vault/tls/vault-cert.pem"
    leader_client_key_file  = "/opt/vault/tls/vault-key.pem"
    leader_ca_cert_file     = "/opt/vault/tls/vault-ca.pem"
    leader_tls_servername   = "eos-vault-node4-az3"
  }
  
  retry_join {
    leader_api_addr         = "https://eos-vault-node5-az3.eos.local:8179"
    leader_client_cert_file = "/opt/vault/tls/vault-cert.pem"
    leader_client_key_file  = "/opt/vault/tls/vault-key.pem"
    leader_ca_cert_file     = "/opt/vault/tls/vault-ca.pem"
    leader_tls_servername   = "eos-vault-node5-az3"
  }
}

# TCP Listener
listener "tcp" {
  address         = "0.0.0.0:8179"
  cluster_address = "0.0.0.0:8180"
  tls_cert_file   = "/opt/vault/tls/vault-cert.pem"
  tls_key_file    = "/opt/vault/tls/vault-key.pem"
  tls_min_version = "tls12"
  tls_cipher_suites = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
}

# Cluster addressing
cluster_addr = "https://10.0.1.10:8180"  # This node's IP
api_addr     = "https://10.0.1.10:8179"  # This node's IP

# Auto-unseal with AWS KMS
seal "awskms" {
  region     = "ap-southeast-2"
  kms_key_id = "alias/eos-vault-unseal"
}

# Hardening
disable_mlock = true  # Required for Raft
ui = true
log_level = "info"
log_format = "json"

# Telemetry
telemetry {
  prometheus_retention_time = "30s"
  disable_hostname          = true
  enable_hostname_label     = true
}

# Limits
max_lease_ttl = "768h"  # 32 days
default_lease_ttl = "168h"  # 7 days
```

**Note:** Nodes 2-5 use identical configuration except:
- `node_id` (unique per node)
- `cluster_addr` (node's own IP:8180)
- `api_addr` (node's own IP:8179)

---

### Port Reference {#port-reference}

#### Required Ports

| Port | Protocol | Purpose | Direction | Notes |
|------|----------|---------|-----------|-------|
| 8179 | TCP | Vault API | Inbound | Client requests, UI access |
| 8180 | TCP | Raft Cluster | Inbound | Inter-node communication |

#### EOS Custom Ports vs HashiCorp Defaults

| Service | EOS Port | HashiCorp Default | Reason for Change |
|---------|----------|-------------------|-------------------|
| Vault API | 8179 | 8200 | EOS design decision |
| Raft Cluster | 8180 | 8201 | Aligns with EOS API port |

#### Firewall Configuration

```bash
# Internal network (node-to-node)
sudo ufw allow from 10.0.0.0/8 to any port 8179 proto tcp comment "Vault API - internal"
sudo ufw allow from 10.0.0.0/8 to any port 8180 proto tcp comment "Raft cluster"

# External access (if needed)
sudo ufw allow from any to any port 8179 proto tcp comment "Vault API - external"

# Verify rules
sudo ufw status numbered
```

**Security Best Practice:** Restrict port 8180 to known Vault node IPs only:
```bash
sudo ufw delete allow 8180
sudo ufw allow from 10.0.1.10 to any port 8180 proto tcp comment "Vault node1"
sudo ufw allow from 10.0.1.11 to any port 8180 proto tcp comment "Vault node2"
sudo ufw allow from 10.0.1.12 to any port 8180 proto tcp comment "Vault node3"
sudo ufw allow from 10.0.1.13 to any port 8180 proto tcp comment "Vault node4"
sudo ufw allow from 10.0.1.14 to any port 8180 proto tcp comment "Vault node5"
```

---

### Security Hardening Checklist {#security-hardening}

#### System Hardening

- [ ] **Disable core dumps** (prevents memory exposure)
  ```bash
  # Add to systemd service
  LimitCORE=0
  ```

- [ ] **Enable file permissions check**
  ```bash
  export VAULT_ENABLE_FILE_PERMISSIONS_CHECK=1
  ```

- [ ] **Restrict SSH access**
  ```bash
  # Allow only specific IPs or jump host
  # /etc/ssh/sshd_config
  AllowUsers *@10.0.0.0/8
  PasswordAuthentication no
  ```

- [ ] **Enable SELinux/AppArmor** (if applicable)
  ```bash
  # Ubuntu with AppArmor
  sudo aa-enforce /etc/apparmor.d/usr.bin.vault
  ```

- [ ] **Disable unnecessary services**
  ```bash
  sudo systemctl list-unit-files --state=enabled
  # Disable anything not needed
  ```

---

#### Vault Configuration Hardening

- [ ] **Use strong TLS configuration**
  ```hcl
  listener "tcp" {
    tls_min_version = "tls12"  # or tls13
    tls_cipher_suites = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
  }
  ```

- [ ] **Set appropriate lease TTLs**
  ```hcl
  max_lease_ttl = "768h"      # 32 days
  default_lease_ttl = "168h"  # 7 days
  ```

- [ ] **Enable audit logging**
  ```bash
  vault audit enable file file_path=/var/log/vault/audit.log
  ```

- [ ] **Restrict root token usage**
  - Disable root token after initial setup
  - Use admin policies instead
  - Regenerate root token only when necessary

---

#### Network Hardening

- [ ] **Use internal network for cluster communication**
  - Place Vault nodes on private subnet
  - No direct internet access
  - Use NAT gateway for outbound only

- [ ] **Implement network segmentation**
  - Separate Vault subnet from application subnet
  - Use security groups/ACLs between layers

- [ ] **Restrict access to port 8180**
  - Only allow communication between Vault nodes
  - Never expose to public internet

- [ ] **Use load balancer for client access**
  - Single entry point
  - SSL termination (optional)
  - Health checking

---

#### Operational Hardening

- [ ] **Implement auto-unseal** (production)
  - AWS KMS / Azure Key Vault / GCP Cloud KMS
  - Eliminates manual unsealing burden
  - Provides audit trail

- [ ] **Distribute unseal keys** (if manual unsealing)
  - Give each key to different person
  - Require 3 of 5 to unseal (threshold)
  - Never store all keys together

- [ ] **Configure automated backups**
  - Daily snapshots minimum
  - Store off-site (S3, Azure Blob, etc.)
  - Test restore process quarterly

- [ ] **Enable monitoring and alerting**
  - Vault down alert
  - Vault sealed alert
  - Quorum loss alert
  - High latency alert
  - Leader change alert

- [ ] **Implement log aggregation**
  - Send audit logs to SIEM
  - Send system logs to centralized logging
  - Retain logs per compliance requirements

- [ ] **Document procedures**
  - Initialization procedure
  - Unsealing procedure (if manual)
  - Backup/restore procedure
  - Incident response runbook
  - Disaster recovery plan

---

#### Access Control Hardening

- [ ] **Implement least privilege policies**
  - No wildcard `*` permissions
  - Specific path-based permissions
  - Time-bound tokens where possible

- [ ] **Use identity-based authentication**
  - LDAP / Active Directory
  - OIDC / SAML
  - Kubernetes auth (for K8s workloads)
  - AppRole (for applications)

- [ ] **Enable MFA for administrative access**
  ```bash
  vault write sys/mfa/method/totp/admin \
    issuer=Vault \
    period=30 \
    key_size=20 \
    algorithm=SHA256 \
    digits=6
  ```

- [ ] **Rotate credentials regularly**
  - Root token: Regenerate quarterly
  - Service tokens: Short TTL with renewal
  - Database credentials: Enable dynamic secrets

---

#### Compliance and Audit

- [ ] **Enable comprehensive audit logging**
  - Log all authentication attempts
  - Log all secret access
  - Log all policy changes
  - Log all configuration changes

- [ ] **Implement log forwarding to SIEM**
  ```bash
  # Example: Forward to Splunk
  vault audit enable syslog tag="vault" facility="AUTH"
  ```

- [ ] **Conduct regular security reviews**
  - Quarterly access review
  - Annual penetration testing
  - Compliance audit (SOC2, PCI-DSS, etc.)

- [ ] **Document security controls**
  - Security policy
  - Access control policy
  - Incident response plan
  - Business continuity plan

---

### Implementation Checklist {#implementation-checklist}

This is a high-level checklist. **For comprehensive step-by-step guidance, see:** `eos-raft-implementation-checklist.md`

#### Phase 1: Planning (2-4 hours)

- [ ] Determine environment (dev/staging/production)
- [ ] Decide cluster size (1/3/5 nodes)
- [ ] Plan availability zone distribution
- [ ] Choose auto-unseal method
- [ ] Design network topology
- [ ] Plan backup strategy
- [ ] Review security requirements
- [ ] Schedule deployment timeline

---

#### Phase 2: Infrastructure (1-2 hours)

- [ ] Provision servers/VMs
- [ ] Configure networking
- [ ] Set up firewall rules
- [ ] Configure DNS (if using hostnames)
- [ ] Set up cloud KMS (if auto-unseal)
- [ ] Prepare monitoring infrastructure

---

#### Phase 3: TLS Certificates (1-2 hours)

- [ ] Generate/obtain TLS certificates
- [ ] Verify SANs include all node IPs/hostnames
- [ ] Deploy certificates to all nodes
- [ ] Set correct permissions (640 for key, 644 for cert)
- [ ] Verify certificate validity

---

#### Phase 4: Vault Installation (30 mins)

- [ ] Install Vault on all nodes
- [ ] Create vault user
- [ ] Create directory structure
- [ ] Deploy configuration files
- [ ] Create systemd service files
- [ ] Enable Vault service

---

#### Phase 5: Cluster Initialization (1-2 hours)

- [ ] Start Vault on first node
- [ ] Initialize Vault
- [ ] Securely store unseal keys/root token
- [ ] Unseal first node (or verify auto-unseal)
- [ ] Join additional nodes (if multi-node)
- [ ] Unseal all nodes (if manual unsealing)
- [ ] Verify cluster formation
- [ ] Enable Autopilot (if production)

---

#### Phase 6: Load Balancer Setup (1-2 hours, production only)

- [ ] Deploy load balancer (HAProxy/NGINX/Cloud LB)
- [ ] Configure health checks (accept 200 and 429)
- [ ] Add all nodes as backends
- [ ] Test load balancer connectivity
- [ ] Configure SSL termination (optional)

---

#### Phase 7: Backup Configuration (30-60 mins)

- [ ] Create backup script
- [ ] Schedule automated backups (cron or Enterprise)
- [ ] Configure off-site storage (S3/Azure/GCP)
- [ ] Test backup script
- [ ] Test restore procedure
- [ ] Document backup/restore process

---

#### Phase 8: Monitoring Setup (2-4 hours)

- [ ] Enable Vault telemetry
- [ ] Configure Prometheus scraping
- [ ] Set up Grafana dashboard
- [ ] Configure alert rules
- [ ] Set up AlertManager
- [ ] Configure notification channels
- [ ] Test alerts

---

#### Phase 9: Security Hardening (2-4 hours)

- [ ] Implement security checklist above
- [ ] Enable audit logging
- [ ] Configure log forwarding
- [ ] Disable root token
- [ ] Create admin policies
- [ ] Configure authentication methods
- [ ] Test access controls

---

#### Phase 10: Testing and Validation (2-4 hours)

- [ ] Test secret read/write
- [ ] Test leader failover
- [ ] Test quorum loss/recovery
- [ ] Test backup/restore
- [ ] Test auto-unseal (if configured)
- [ ] Test load balancer (if configured)
- [ ] Verify monitoring/alerting
- [ ] Load testing (optional)

---

#### Phase 11: Documentation (2-3 hours)

- [ ] Document cluster topology
- [ ] Document network configuration
- [ ] Document backup procedures
- [ ] Document restore procedures
- [ ] Create operational runbooks
- [ ] Document troubleshooting steps
- [ ] Create disaster recovery plan
- [ ] Train team on operations

---

#### Phase 12: Production Go-Live (1-2 hours)

- [ ] Final verification of all systems
- [ ] Notify stakeholders of go-live
- [ ] Migrate applications to new Vault
- [ ] Monitor closely for 24-48 hours
- [ ] Conduct post-implementation review

**Total Estimated Time:**
- **Development (Single Node):** 4-6 hours
- **Testing (3-Node):** 8-12 hours
- **Production (5-Node):** 16-24 hours

---

## Appendices

### Appendix A: Related Documentation

This specification should be read alongside:

1. **eos-raft-decision-tree.md**
   - Comprehensive decision flowcharts
   - Environment-specific guidance
   - Unseal strategy decisions
   - Networking architecture options
   - Backup strategy decisions

2. **eos-raft-implementation-checklist.md**
   - Detailed step-by-step instructions
   - Phase-by-phase implementation
   - Pre-flight checks
   - Testing procedures
   - Rollback procedures

3. **eos-raft-integration-guide.md**
   - Technical deep dive
   - Configuration differences (file vs Raft)
   - Migration procedures
   - Testing strategies
   - Code changes for EOS

4. **raft-vs-file-architecture.md**
   - Visual architecture comparison
   - How Raft consensus works
   - Failure scenarios
   - Recovery procedures
   - Recommended cluster sizes

---

### Appendix B: Quick Reference Commands

#### Cluster Management
```bash
# List Raft peers
vault operator raft list-peers

# Check current leader
vault read sys/leader

# Join node to cluster
vault operator raft join https://leader.example.com:8179

# Remove node from cluster
vault operator raft remove-peer <node-id>

# Check Autopilot configuration
vault operator raft autopilot get-config

# Check Autopilot state
vault operator raft autopilot state
```

#### Snapshots
```bash
# Take snapshot
vault operator raft snapshot save backup.snap

# Inspect snapshot
vault operator raft snapshot inspect backup.snap

# Restore snapshot
vault operator raft snapshot restore -force backup.snap
```

#### Unsealing
```bash
# Check seal status
vault status

# Unseal (manual)
vault operator unseal <key>

# Check unseal progress
vault operator unseal -status

# Seal vault
vault operator seal
```

#### Health Checks
```bash
# API health check
curl -k https://localhost:8179/v1/sys/health

# Detailed health (JSON)
curl -k https://localhost:8179/v1/sys/health?standbyok=true

# Metrics (Prometheus format)
curl -k https://localhost:8179/v1/sys/metrics?format=prometheus
```

---

### Appendix C: Common Error Messages

#### "transport: authentication handshake failed: x509: certificate is valid for X, not Y"
**Cause:** TLS certificate doesn't have correct SANs  
**Fix:** Regenerate certificate with all node IPs/hostnames in SANs

#### "failed to join raft cluster: failed to retrieve cluster information"
**Cause:** Cannot reach leader or TLS issues  
**Fix:** Verify network connectivity and TLS configuration

#### "cluster leadership lost while committing log"
**Cause:** Network partition or node failures  
**Fix:** Check network connectivity, bring failed nodes back online

#### "rpc error: code = Unavailable desc = transport is closing"
**Cause:** Raft cluster communication issues  
**Fix:** Check port 8180 is open and accessible between nodes

#### "local node not found in the peer set"
**Cause:** Node not properly joined to cluster  
**Fix:** Re-join node or remove and re-add peer

---

### Appendix D: Performance Tuning

#### Disk Performance

Raft is disk I/O intensive. Use:
- **SSDs** (NVMe preferred)
- **Separate disk for /opt/vault/data** (not OS disk)
- **ext4 or xfs filesystem**
- **noatime mount option**

```bash
# Add to /etc/fstab
/dev/sdb1  /opt/vault/data  ext4  noatime,nodiratime  0  2
```

#### Network Performance

Minimize latency between nodes:
- **Same region** (ideally)
- **High bandwidth** (1 Gbps minimum, 10 Gbps ideal)
- **Low latency** (<10ms between nodes ideal)

Test network latency:
```bash
# Ping test
ping -c 100 node2.example.com

# iperf3 bandwidth test
# On node1:
iperf3 -s

# On node2:
iperf3 -c node1.example.com -t 30
```

#### Raft Performance Multiplier

```hcl
storage "raft" {
  performance_multiplier = 1  # Production (most aggressive)
  # performance_multiplier = 5  # Default
  # performance_multiplier = 10 # Development (least aggressive)
}
```

**Lower values = higher performance but more resource usage**

---

### Appendix E: Disaster Recovery Scenarios

#### Scenario 1: Single Node Failure (5-Node Cluster)

**Impact:** None (cluster continues normally)  
**Action:** Optional - replace node when convenient

**Procedure:**
```bash
# 1. Remove failed node from cluster
vault operator raft remove-peer <failed-node-id>

# 2. Provision new node
# 3. Join new node to cluster
vault operator raft join https://leader.example.com:8179

# 4. Unseal new node (if manual unsealing)
```

---

#### Scenario 2: Leader Node Failure

**Impact:** Brief unavailability (~1-5 seconds) while new leader elected  
**Action:** None required (automatic failover)

**What happens:**
1. Followers detect leader failure (no heartbeat)
2. Election triggered
3. New leader elected (majority vote)
4. Cluster resumes operation

**Monitoring:**
```bash
# Watch for leader changes
watch -n 1 'vault read sys/leader'
```

---

#### Scenario 3: Quorum Loss (3+ Nodes Down in 5-Node Cluster)

**Impact:** Cluster completely unavailable  
**Action:** URGENT - bring nodes back online or restore from snapshot

**Recovery Options:**

**Option 1: Bring failed nodes back online**
```bash
# On each failed node:
sudo systemctl start vault
vault operator unseal <keys>  # If manual unsealing

# Verify cluster recovers
vault operator raft list-peers
```

**Option 2: Restore from snapshot** (if nodes unrecoverable)
```bash
# 1. Stop all Vault nodes except one
sudo systemctl stop vault  # On nodes 2-5

# 2. Restore snapshot on remaining node
vault operator raft snapshot restore -force latest-backup.snap

# 3. Restart all nodes
sudo systemctl start vault  # On all nodes

# 4. Unseal all nodes
```

---

#### Scenario 4: Complete Cluster Loss

**Impact:** Total data loss if no backups  
**Action:** Restore from backup

**Recovery:**
```bash
# 1. Rebuild infrastructure (5 nodes)
# 2. Install Vault on all nodes
# 3. Deploy configuration
# 4. Initialize first node
vault operator init

# 5. Restore snapshot
vault operator raft snapshot restore -force latest-backup.snap

# 6. Join other nodes
# 7. Verify data integrity
vault kv list secret/
```

---

#### Scenario 5: Entire Availability Zone Loss

**Impact:** 
- 5-node cluster (2 nodes per AZ1/AZ2, 1 in AZ3): Cluster survives ✅
- 3-node cluster (1 node per AZ): Cluster down ❌

**With 5-node cluster properly distributed:**
- Lose AZ1 (2 nodes): 3 nodes remain = quorum maintained
- Lose AZ2 (2 nodes): 3 nodes remain = quorum maintained
- Lose AZ3 (1 node): 4 nodes remain = quorum maintained

**This is why 5 nodes across 3 AZs is recommended.**

---

### Appendix F: Compliance and Regulatory Considerations

#### PCI-DSS

Vault can help meet PCI-DSS requirements:
- **Requirement 3.4**: Encryption of cardholder data
- **Requirement 3.5**: Key management
- **Requirement 8**: Access control
- **Requirement 10**: Audit logging

**Vault features for PCI-DSS:**
- Transit secrets engine (encryption-as-a-service)
- Dynamic secrets with short TTLs
- Comprehensive audit logging
- Strong access controls

---

#### SOC 2

Vault supports SOC 2 compliance:
- **Availability**: High availability with Raft
- **Confidentiality**: Encryption at rest and in transit
- **Processing Integrity**: Audit logs track all access
- **Privacy**: Access controls limit data exposure

**Evidence collection:**
- Audit logs → SIEM
- Policy configurations
- Access control policies
- Backup/DR procedures

---

#### HIPAA

For healthcare data:
- Use Vault to store and encrypt PHI
- Enable comprehensive audit logging
- Implement strong access controls
- Use time-bound tokens
- Regular security reviews

---

#### GDPR

For EU personal data:
- Implement data minimization (short TTLs)
- Enable audit trail (access logging)
- Implement right to erasure (secret deletion)
- Use encryption (transit engine)

---

### Appendix G: Glossary

**Raft**: Consensus algorithm for distributed systems  
**Quorum**: Minimum number of nodes needed for cluster operation  
**Leader**: Node that handles writes and coordinates replication  
**Follower**: Node that replicates data from leader  
**Standby**: Another term for follower  
**Autopilot**: Automated cluster management feature  
**Auto-unseal**: Automatic unsealing using external KMS  
**Shamir's Secret Sharing**: Algorithm for splitting keys into shares  
**Seal/Unseal**: Locking/unlocking Vault's encryption barrier  
**Root Token**: Superuser token with all permissions  
**Policy**: Access control rules in Vault  
**Secrets Engine**: Plugin for storing/generating secrets  
**Auth Method**: Plugin for authentication  
**TTL**: Time To Live (token/lease expiration time)  
**KMS**: Key Management Service (cloud encryption keys)  
**HSM**: Hardware Security Module (physical encryption device)  
**SAN**: Subject Alternative Name (TLS certificate field)  
**AZ**: Availability Zone (data center)

---

### Appendix H: Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 0.0 | 2024 | Initial specification (file storage) | - |
| 0.1 | Oct 2025 | Red team review, identified file storage issues | Red Team |
| 1.0 | Oct 13, 2025 | Complete rewrite with Raft as primary, integrated 4 comprehensive Raft guides | Henry & Claude |

---

### Appendix I: Getting Help

#### Official HashiCorp Resources
- **Documentation**: https://developer.hashicorp.com/vault/docs
- **Community Forum**: https://discuss.hashicorp.com/c/vault
- **GitHub Issues**: https://github.com/hashicorp/vault/issues
- **Enterprise Support**: https://support.hashicorp.com (if licensed)

#### Code Monkey Cybersecurity
- **Internal Wiki**: [Link to internal documentation]
- **Slack Channel**: #eos-vault
- **On-Call**: [Pagerduty/on-call info]

#### Emergency Contacts
- **Security Incidents**: [Security team contact]
- **Infrastructure Issues**: [Infrastructure team contact]
- **Vault Cluster Down**: [Escalation procedure]

---

## Conclusion

This specification provides comprehensive guidance for deploying HashiCorp Vault with Integrated Storage (Raft) in the EOS platform. The key takeaways:

1. **Raft is the recommended storage backend** for all production deployments
2. **File storage should only be used** for development and learning
3. **5-node clusters across 3 AZs** provide optimal production resilience
4. **Auto-unseal is strongly recommended** for production environments
5. **Comprehensive monitoring and backup** are essential for operations

For step-by-step implementation, follow the detailed guides:
- Decision-making: `eos-raft-decision-tree.md`
- Implementation: `eos-raft-implementation-checklist.md`
- Technical deep dive: `eos-raft-integration-guide.md`
- Architecture: `raft-vs-file-architecture.md`

**Remember:** The time invested in proper Raft implementation pays off with:
- High availability and automatic failover
- Simplified operations with Autopilot
- Production-ready architecture
- Compliance with HashiCorp's recommendations
- Future-proof design (required for Vault Enterprise 1.12.0+)

---

**Document Status:** ✅ Production Ready  
**Next Review Date:** January 2026 (or when Vault 1.21.x is released)  
**Maintained By:** Code Monkey Cybersecurity - EOS Team
