# Quick Start Guide for Claude Code Implementation

**Ready to implement?** Here's exactly what to do.

---

## 📦 What You Have

### 1. [Executive Summary](computer:///mnt/user-data/outputs/executive-summary-review-first.md) ✅
- Overview of decisions made
- Architectural reasoning
- What questions were answered

### 2. [Main Implementation Plan](computer:///mnt/user-data/outputs/bionicgpt-nomad-hecate-implementation-plan.md) ✅ 
- 113+ pages of complete implementation details
- All Go code for all packages
- Nomad job definitions
- Testing checklist

### 3. [Implementation Addendum](computer:///mnt/user-data/outputs/implementation-addendum-clarified.md) ✅
- Updated with your clarifications
- Tailscale-specific implementation
- Vault integration details
- Caddy Admin API usage
- Consul joining existing cluster

### 4. [Architecture Diagram](computer:///mnt/user-data/outputs/bionicgpt-architecture-diagram.html) ✅
- Visual system overview
- Authentication flow
- All components and connections

---

## 🎯 One-Time Prerequisites (Do This First!)

Before running `eos create bionicgpt`, complete these manual steps:

### 1. Install Tailscale (Both Nodes)

**Cloud node:**
```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
# Note the Tailscale IP shown
```

**Local node:**
```bash
curl -fsSL https://tailscale.com/install.sh | sh
sudo tailscale up
# Note the Tailscale IP shown
```

**Verify connectivity:**
```bash
# From local node, ping cloud node via Tailscale
tailscale ping cloud-node-name
```

### 2. Create Authentik API Token

**Steps:**
1. Navigate to: `https://auth.codemonkey.ai/if/admin/#/core/tokens`
2. Click "Create Token"
3. Configure:
   - **Identifier:** `eos-automation`
   - **User:** Your admin user
   - **Description:** EOS CLI automation token
   - **Expires:** Never (or set long expiry)
4. Copy the generated token (starts with `ak_...`)

**Store in Vault:**
```bash
vault kv put secret/bionicgpt/authentik \
    api_key="ak_YOUR_TOKEN_HERE" \
    base_url="https://auth.codemonkey.ai"
```

### 3. Verify Consul Access

**From local node:**
```bash
# Get cloud Tailscale IP
CLOUD_IP=$(tailscale ip cloud-node-name)

# Test Consul API
curl http://$CLOUD_IP:8500/v1/status/leader
# Should return something like: "10.2.0.1:8300"
```

### 4. Verify Caddy Admin API

**From local node:**
```bash
# Test Caddy admin API
curl http://$CLOUD_IP:2019/
# Should return basic admin API info
```

**If Caddy admin API is not exposed on Tailscale:**

Edit Hecate docker-compose.yml to bind Caddy admin API:
```yaml
services:
  caddy:
    # ... existing config ...
    command: caddy run --config /etc/caddy/Caddyfile --adapter caddyfile --admin 0.0.0.0:2019
```

Or in Caddyfile:
```caddyfile
{
    admin 0.0.0.0:2019
}
```

### 5. Store Azure OpenAI Credentials in Vault

```bash
vault kv put secret/bionicgpt/azure \
    endpoint="https://YOUR_RESOURCE.openai.azure.com" \
    api_key="YOUR_AZURE_API_KEY" \
    chat_deployment="YOUR_DEPLOYMENT_NAME"
```

### 6. Generate OAuth Cookie Secret

```bash
# Generate a random 32-byte secret
COOKIE_SECRET=$(openssl rand -base64 32)

# Store in Vault (will be populated by eos with OAuth client details)
vault kv put secret/bionicgpt/oauth \
    cookie_secret="$COOKIE_SECRET"
```

---

## 🚀 Give This to Claude Code

### Paste This Prompt:

```
I need you to implement the `eos create bionicgpt` command for our CLI tool.

I have three documents for you:

1. **Main Implementation Plan** (113 pages)
   - File: bionicgpt-nomad-hecate-implementation-plan.md
   - Contains: Complete architecture, all Go code, Nomad jobs, testing

2. **Implementation Addendum** (clarifications)
   - File: implementation-addendum-clarified.md
   - Contains: Updated mechanics for Tailscale, Vault, Caddy API, Consul

3. **Existing EOS CLI code** (for patterns)
   - Your existing eos codebase to follow patterns

## Context

We're deploying BionicGPT (an on-premise ChatGPT replacement) with:
- **Orchestration:** Nomad (not Kubernetes)
- **Reverse Proxy:** Hecate framework (Caddy + Authentik on cloud node)
- **Service Discovery:** Consul (existing cluster)
- **Authentication:** Authentik (OAuth2/OIDC)
- **VPN:** Tailscale (connecting cloud and local nodes)
- **Secrets:** HashiCorp Vault

## Prerequisites Completed

The user has already:
✅ Installed Tailscale on both nodes
✅ Created Authentik API token and stored in Vault
✅ Verified Consul access from local node
✅ Verified Caddy admin API is accessible
✅ Stored Azure OpenAI credentials in Vault

## Implementation Phases

Please implement the 9 phases from the main implementation plan:

**Phase 1:** Prerequisites & Setup
- Update go.mod with dependencies
- Create package structure

**Phase 2:** Command Definition
- Create cmd/create/bionicgpt.go with all flags
- Follow existing eos patterns

**Phase 3:** Preflight Checks
- Implement all checks (Tailscale, Nomad, Consul, Docker, Vault, Authentik, Ollama, ports, disk)
- Use mechanics from addendum for Tailscale checks

**Phase 4:** Authentik Integration
- Implement pkg/authentik/client.go (OAuth2 provider, groups, applications)
- Implement pkg/bionicgpt/authentik.go (configuration logic)
- Use Vault integration from addendum

**Phase 5:** Consul Integration
- Implement pkg/consul/client.go (service registration)
- Implement pkg/bionicgpt/consul.go (join existing cluster)
- Use Tailscale IPs for Consul configuration

**Phase 6:** Nomad Deployment
- Implement pkg/nomad/client.go (job submission)
- Implement pkg/bionicgpt/nomad.go (deployment logic)
- Create Nomad job templates

**Phase 7:** Hecate Integration
- Implement pkg/hecate/client.go (Caddy Admin API)
- Implement pkg/bionicgpt/hecate.go (configuration)
- Use API-based updates (no SSH)

**Phase 8:** Health Checks
- Implement pkg/bionicgpt/health.go (wait for services)
- Use Consul for health checking

**Phase 9:** Main Installer
- Implement pkg/bionicgpt/installer.go (orchestration)
- Wire all phases together

## Key Implementation Notes

1. **Tailscale IPs:** Use `tailscale ip hostname` to get IP addresses
2. **Vault Paths:**
   - Authentik: `secret/data/bionicgpt/authentik`
   - OAuth: `secret/data/bionicgpt/oauth`
   - Azure: `secret/data/bionicgpt/azure`
   - Database: `secret/data/bionicgpt/db`
3. **Caddy Updates:** Use Admin API POST to /load endpoint
4. **Consul Join:** Configure local agent to join existing cluster
5. **Error Messages:** Provide helpful troubleshooting info

## Testing

After implementation, we should be able to run:

```bash
# Dry run
eos create bionicgpt \
  --domain chat.codemonkey.ai \
  --cloud-node cloud-hecate \
  --dry-run

# Actual deployment
eos create bionicgpt \
  --domain chat.codemonkey.ai \
  --cloud-node cloud-hecate \
  --auth-provider authentik \
  --auth-url https://auth.codemonkey.ai \
  --use-hecate \
  --local-embeddings
```

Please implement this systematically, phase by phase, following the detailed specifications in both documents.

Let me know if you need clarification on any part!
```

---

## 📋 What Claude Code Will Do

Claude Code will implement:

1. ✅ All Go packages (bionicgpt, authentik, consul, nomad, hecate)
2. ✅ All command flags and validation
3. ✅ All preflight checks
4. ✅ Authentik API integration
5. ✅ Consul agent configuration
6. ✅ Nomad job submission
7. ✅ Caddy Admin API integration
8. ✅ Health check logic
9. ✅ Complete error handling
10. ✅ Helpful error messages

**Estimated time:** 18-22 hours of implementation

---

## ✅ After Implementation

### Test the Command

**1. Dry run first:**
```bash
eos create bionicgpt \
  --domain chat.codemonkey.ai \
  --cloud-node cloud-hecate \
  --auth-provider authentik \
  --auth-url https://auth.codemonkey.ai \
  --use-hecate \
  --local-embeddings \
  --dry-run
```

**2. Actual deployment:**
```bash
eos create bionicgpt \
  --domain chat.codemonkey.ai \
  --cloud-node cloud-hecate \
  --auth-provider authentik \
  --auth-url https://auth.codemonkey.ai \
  --use-hecate \
  --local-embeddings
```

**3. Verify deployment:**
```bash
# Check Nomad job status
nomad job status bionicgpt

# Check Consul services
consul catalog services

# Check service health
consul watch -type=service -service=bionicgpt

# Test the URL
curl -I https://chat.codemonkey.ai
# Should redirect to Authentik
```

**4. Manual verification:**
1. Visit `https://chat.codemonkey.ai`
2. Should redirect to Authentik login
3. Log in with test user
4. Should redirect back to BionicGPT
5. Verify you can chat
6. Upload a document and verify embeddings work

---

## 🐛 Troubleshooting

### If preflight fails:

**Tailscale not connected:**
```bash
sudo tailscale up
tailscale status
```

**Authentik token not found:**
```bash
vault kv get secret/bionicgpt/authentik
# If missing, recreate and store
```

**Consul not reachable:**
```bash
# Check firewall on cloud node
sudo ufw status
# Ensure port 8500 is open to Tailscale subnet

# Verify Consul is running
consul members
```

**Caddy Admin API not accessible:**
```bash
# Check if Caddy is running
docker ps | grep caddy

# Check Caddy admin config
curl http://localhost:2019/config/ | jq '.admin'
```

### If deployment fails:

**Check Nomad job:**
```bash
nomad job status bionicgpt
nomad alloc logs <ALLOC_ID>
```

**Check Consul services:**
```bash
consul catalog services
consul health service bionicgpt
```

**Check Vault secrets:**
```bash
vault kv get secret/bionicgpt/oauth
vault kv get secret/bionicgpt/azure
vault kv get secret/bionicgpt/db
```

---

## 📊 Success Criteria

Deployment is successful when:

✅ All preflight checks pass
✅ Authentik provider created
✅ Authentik groups created (bionicgpt-superadmin, bionicgpt-demo-tenant)
✅ Nomad job running (all allocations healthy)
✅ All services registered in Consul
✅ All health checks passing
✅ Caddy routing configured
✅ https://chat.codemonkey.ai redirects to Authentik
✅ Can log in and access BionicGPT
✅ LLM chat works
✅ Document upload works (embeddings)

---

## 🎯 Summary

**You now have:**
1. ✅ Complete implementation specification
2. ✅ All code templates ready
3. ✅ Clear prerequisites documented
4. ✅ Detailed troubleshooting guide

**Next steps:**
1. Complete one-time prerequisites (15 min)
2. Give documents to Claude Code (5 min)
3. Wait for implementation (18-22 hours)
4. Test and verify (30 min)
5. Start using BionicGPT! 🎉

**Questions?** Everything should be documented, but let me know if you need clarification on any part!
