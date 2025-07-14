# Hecate Advanced Management Functions

*Last Updated: 2025-01-14*

This document describes how to use the advanced helper functions integrated into the Eos framework for managing your Hecate reverse proxy infrastructure.

## Overview

The new helper functions provide comprehensive management capabilities for:
- **Route Management**: Create, update, and delete reverse proxy routes
- **Authentication Policies**: Manage identity-aware access control via Authentik
- **State Reconciliation**: Ensure configuration consistency across your infrastructure
- **Secret Rotation**: Zero-downtime credential management
- **Transaction Support**: Safe rollback for multi-step operations

## Route Management

### Creating Routes

Routes map domains to upstream backend services with optional authentication and health checks.

```bash
# Basic route creation
eos create hecate route --domain app.example.com --upstream localhost:3000

# Route with authentication policy
eos create hecate route --domain api.example.com --upstream localhost:8080 --auth-policy api-users

# Route with MFA requirement
eos create hecate route --domain secure.example.com --upstream localhost:443 --require-mfa

# Route with custom headers and health check
eos create hecate route \
  --domain service.example.com \
  --upstream backend:8080 \
  --headers "X-Custom-Header=value" \
  --headers "X-Another-Header=another-value" \
  --health-check-path /health \
  --health-check-interval 15s
```

### Updating Routes

```bash
# Update route upstream
eos update hecate route --domain app.example.com --upstream new-backend:3001

# Update authentication policy
eos update hecate route --domain app.example.com --auth-policy new-policy

# Add health check to existing route
eos update hecate route \
  --domain app.example.com \
  --health-check-path /api/health \
  --health-check-interval 30s
```

### Deleting Routes

```bash
# Delete a route
eos delete hecate route --domain app.example.com

# Force delete (skip usage checks)
eos delete hecate route --domain app.example.com --force
```

## Authentication Policy Management

### Creating Authentication Policies

```bash
# Basic authentication policy
eos create hecate auth-policy \
  --name api-users \
  --provider authentik \
  --flow default-authentication-flow

# Policy with group restrictions
eos create hecate auth-policy \
  --name admin-only \
  --provider authentik \
  --groups admin,superuser \
  --require-mfa

# Policy with custom metadata
eos create hecate auth-policy \
  --name partner-access \
  --provider authentik \
  --metadata "partner_id=required" \
  --metadata "contract_status=active"
```

### Listing Policies

```bash
# List all authentication policies
eos list hecate auth-policies

# Show policy details
eos read hecate auth-policy --name api-users
```

## State Reconciliation

State reconciliation ensures your runtime configuration matches your desired state from Git or configuration management.

### Running Reconciliation

```bash
# Reconcile all components
eos update hecate state reconcile

# Dry run to see what would change
eos update hecate state reconcile --dry-run

# Reconcile specific component
eos update hecate state reconcile --component routes

# Force reconciliation (skip lock)
eos update hecate state reconcile --force

# Reconcile from specific Git commit
eos update hecate state reconcile --from-commit abc123
```

### State Backup and Restore

```bash
# Backup current state
eos backup hecate state --output /path/to/backup.yaml

# Restore from backup
eos backup hecate restore --from /path/to/backup.yaml
```

## Secret Rotation

Manage secrets with zero-downtime rotation strategies.

### Rotating Secrets

```bash
# Rotate with dual-secret strategy (zero downtime)
eos update hecate secret rotate --name authentik-api-token --strategy dual-secret

# Immediate rotation (brief downtime)
eos update hecate secret rotate --name caddy-admin-password --strategy immediate

# Rotate all secrets
eos update hecate secret rotate-all --strategy dual-secret
```

### Secret Status

```bash
# Check secret rotation status
eos read hecate secret status --name authentik-api-token

# List all secrets and rotation status
eos list hecate secrets --show-rotation-status
```

## Upstream Management

### Creating Upstreams

```bash
# Create load-balanced upstream
eos create hecate upstream \
  --name api-backend \
  --servers "10.0.1.10:8080,10.0.1.11:8080,10.0.1.12:8080" \
  --load-balancer round_robin \
  --health-check-path /health

# Upstream with custom timeout
eos create hecate upstream \
  --name slow-backend \
  --servers "localhost:3000" \
  --timeout 60s
```

### Managing Upstreams

```bash
# Add server to upstream
eos update hecate upstream --name api-backend --add-server 10.0.1.13:8080

# Remove server from upstream
eos update hecate upstream --name api-backend --remove-server 10.0.1.10:8080

# Change load balancing strategy
eos update hecate upstream --name api-backend --load-balancer least_conn
```

## Progressive Rollout

Deploy changes gradually with canary deployments.

```bash
# Start canary deployment (10% traffic)
eos update hecate route \
  --domain app.example.com \
  --canary-upstream new-backend:3001 \
  --canary-percentage 10

# Increase canary traffic
eos update hecate route \
  --domain app.example.com \
  --canary-percentage 50

# Complete rollout
eos update hecate route \
  --domain app.example.com \
  --promote-canary

# Rollback canary
eos update hecate route \
  --domain app.example.com \
  --rollback-canary
```

## Monitoring and Health

### Route Health Status

```bash
# Check all routes health
eos read hecate health

# Check specific route
eos read hecate route health --domain app.example.com

# Continuous monitoring
eos read hecate monitor --interval 30s
```

### Metrics and Analytics

```bash
# Show route metrics
eos read hecate metrics --domain app.example.com

# Export metrics for time range
eos read hecate metrics \
  --from "2024-01-01" \
  --to "2024-01-31" \
  --format prometheus
```

## Advanced Configuration

### Custom Middleware

```bash
# Add rate limiting
eos update hecate route \
  --domain api.example.com \
  --middleware "rate-limit:100/minute"

# Add request transformation
eos update hecate route \
  --domain api.example.com \
  --middleware "transform:strip-prefix:/api"
```

### TLS Configuration

```bash
# Custom TLS settings
eos update hecate route \
  --domain secure.example.com \
  --tls-min-version 1.3 \
  --tls-ciphers "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384"

# Use custom certificate
eos update hecate route \
  --domain app.example.com \
  --tls-cert /path/to/cert.pem \
  --tls-key /path/to/key.pem
```

## Disaster Recovery

### Backup Strategies

```bash
# Full backup
eos backup hecate full --destination s3://backup-bucket/hecate/

# Incremental backup
eos backup hecate incremental --since "2024-01-01"

# Backup specific components
eos backup hecate \
  --components "routes,auth-policies" \
  --destination /backup/hecate/
```

### Recovery Procedures

```bash
# Restore from backup
eos backup hecate restore --from s3://backup-bucket/hecate/latest

# Partial restore
eos backup hecate restore \
  --from /backup/hecate/2024-01-15.tar.gz \
  --components routes

# Verify restore
eos read hecate verify --against-backup /backup/hecate/latest
```

## Integration Examples

### GitOps Workflow

```yaml
# .hecate/routes/app.yaml
apiVersion: hecate.io/v1
kind: Route
metadata:
  name: app-route
spec:
  domain: app.example.com
  upstream: app-backend:3000
  authPolicy: standard-users
  tls:
    autoHTTPS: true
    forceHTTPS: true
  healthCheck:
    path: /health
    interval: 30s
```

```bash
# Apply from Git
eos update hecate apply --from-git .hecate/

# Validate before applying
eos update hecate validate --from-git .hecate/
```

### Terraform Integration

```hcl
resource "hecate_route" "app" {
  domain   = "app.example.com"
  upstream = "localhost:3000"
  
  auth_policy = hecate_auth_policy.users.name
  
  health_check {
    path     = "/health"
    interval = "30s"
  }
}

resource "hecate_auth_policy" "users" {
  name       = "app-users"
  provider   = "authentik"
  require_mfa = true
  
  groups = ["users", "staff"]
}
```

## Best Practices

1. **Always use health checks** for production routes
2. **Implement authentication policies** for any public-facing services
3. **Use state reconciliation** regularly to catch configuration drift
4. **Rotate secrets** on a regular schedule (monthly recommended)
5. **Test changes** with dry-run before applying
6. **Monitor route health** continuously
7. **Backup state** before major changes
8. **Use GitOps** for configuration management
9. **Implement progressive rollouts** for critical services
10. **Document your policies** and keep them in version control

## Troubleshooting

### Common Issues

```bash
# Debug route issues
eos read hecate debug --domain app.example.com

# Check Caddy configuration
eos read hecate config caddy

# Check Authentik connection
eos read hecate test auth --provider authentik

# Validate DNS records
eos read hecate validate dns --domain app.example.com
```

### Emergency Procedures

```bash
# Bypass authentication (emergency only!)
eos update hecate route --domain app.example.com --auth-bypass --duration 1h

# Failover to backup upstream
eos update hecate route --domain app.example.com --failover

# Emergency rollback
eos update hecate rollback --to-timestamp "2024-01-15T10:00:00Z"
```

## Security Considerations

1. **API Tokens**: Store in Vault, rotate regularly
2. **TLS**: Always use TLS 1.2+ for routes
3. **Authentication**: Require MFA for administrative access
4. **Audit Logs**: Enable comprehensive logging
5. **Network Isolation**: Use private networks for backend communication
6. **Secret Management**: Use dual-secret rotation strategy
7. **Access Control**: Implement least-privilege policies
8. **Monitoring**: Alert on authentication failures
9. **Backup Encryption**: Encrypt all backups at rest
10. **Compliance**: Regular security audits

This advanced management system provides the foundation for operating a secure, reliable, and scalable reverse proxy infrastructure with Hecate.