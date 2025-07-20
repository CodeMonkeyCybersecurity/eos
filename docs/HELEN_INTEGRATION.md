# Helen Integration Specifications

*Last Updated: 2025-01-20*

## Overview

Helen is a dual-mode website deployment platform within the eos infrastructure compiler framework. It supports both static website hosting and full Ghost CMS deployments, all orchestrated through Nomad and exposed via the Hecate reverse proxy.

## Architecture

Helen follows the eos dual-layer architecture:

- **Infrastructure Layer (SaltStack)**: Manages prerequisites like Docker, Nomad, Consul
- **Application Layer (Nomad)**: Deploys Helen as containerized workload

## Deployment Modes

### 1. Static Mode (Default)
- **Purpose**: Serve static HTML/CSS/JS files
- **Container**: nginx:alpine with security hardening
- **Use Cases**: Hugo sites, Jekyll builds, plain HTML
- **Resource Usage**: Minimal (128MB RAM, 500MHz CPU)

### 2. Ghost Mode
- **Purpose**: Full Ghost CMS deployment
- **Container**: ghost:5-alpine or custom build
- **Use Cases**: Dynamic blogs, content management
- **Database**: MySQL or SQLite
- **Resource Usage**: Higher (1GB+ RAM, 1000MHz+ CPU)

## Command Structure

```bash
eos create helen [flags]
```

### Common Flags
- `--mode`: Deployment mode ('static' or 'ghost')
- `--domain`: Required domain name for Hecate integration
- `--namespace`: Nomad namespace (default: helen)
- `--port`: Internal port (default: 8009)
- `--vault-addr`: Vault server address
- `--nomad-addr`: Nomad server address

### Static Mode Flags
- `--html-path`: Path to static files (default: ./public)
- `--cpu`: CPU allocation in MHz
- `--memory`: Memory allocation in MB

### Ghost Mode Flags
- `--environment`: dev/staging/production
- `--git-repo`: Git repository for configuration
- `--database`: mysql or sqlite
- `--enable-auth`: Enable Authentik authentication
- `--enable-webhook`: Enable CI/CD webhook
- `--ghost-instances`: Number of instances

## Implementation Flow

### Static Mode Deployment

1. **ASSESS Phase**
   - Verify Nomad availability
   - Check HTML path exists
   - Validate domain configuration

2. **INTERVENE Phase**
   - Create Nomad job specification
   - Deploy nginx container
   - Configure Consul service

3. **EVALUATE Phase**
   - Verify deployment health
   - Configure Hecate route
   - Display access information

### Ghost Mode Deployment

1. **ASSESS Phase**
   - Check prerequisites (Docker, Nomad, database)
   - Validate Git repository (if specified)
   - Verify Vault connectivity

2. **INTERVENE Phase**
   - Clone/update Git repository
   - Create Vault secrets
   - Deploy Ghost container(s)
   - Configure database
   - Set up persistent volumes

3. **EVALUATE Phase**
   - Wait for Ghost health check
   - Configure Hecate routes
   - Set up CI/CD webhook (if enabled)

## Integration Points

### Vault Integration
- **Static Mode**: Stores deployment metadata
- **Ghost Mode**: Stores database credentials, mail settings, API keys

### Consul Integration
- Service registration with health checks
- Service discovery for internal communication
- DNS resolution for services

### Hecate Integration
- Automatic route configuration
- SSL termination
- Optional Authentik authentication
- WebSocket support for Ghost admin

### Nomad Integration
- Job orchestration
- Blue-green deployments
- Resource allocation
- Health monitoring

## Security Considerations

### Static Mode
- Read-only nginx container
- No server-side execution
- Security headers configured
- Rate limiting via Hecate

### Ghost Mode
- Database credentials in Vault
- Network isolation
- Regular security updates
- Optional authentication layer

## Persistent Storage

### Static Mode
- No persistent storage needed
- Files served from deployment directory

### Ghost Mode
- `/var/lib/ghost/content`: User uploads, themes
- Database storage (MySQL or local SQLite)
- Automatic backup integration

## Deployment Examples

### Basic Static Site
```bash
eos create helen --domain blog.example.com
```

### Ghost CMS with MySQL
```bash
eos create helen \
  --mode ghost \
  --domain blog.example.com \
  --database mysql \
  --enable-auth
```

### Staging Environment
```bash
eos create helen \
  --mode ghost \
  --domain staging.blog.example.com \
  --environment staging \
  --git-repo https://github.com/myorg/helen-config.git
```

## CI/CD Integration

When `--enable-webhook` is used:

1. Webhook endpoint created at `/webhook/helen`
2. Accepts POST requests with deployment triggers
3. Validates webhook secret from Vault
4. Triggers blue-green deployment
5. Automatic rollback on failure

## Monitoring and Maintenance

### Health Checks
- **Static**: HTTP GET / returns 200
- **Ghost**: HTTP GET /ghost/api/admin/site/

### Logs
```bash
# View logs
nomad alloc logs -job helen-[namespace]

# Follow logs
nomad alloc logs -f -job helen-[namespace]
```

### Updates
```bash
# Update deployment
eos update helen --mode [mode] --namespace [namespace]

# Scale Ghost instances
eos update helen --mode ghost --ghost-instances 3
```

### Backups
```bash
# Backup Ghost content and database
eos backup helen --environment [env]
```

## Troubleshooting

### Common Issues

1. **Port Conflicts**: Check if port 8009 is available
2. **Domain Resolution**: Ensure DNS points to Hecate
3. **Database Connection**: Verify database credentials in Vault
4. **Git Access**: Check SSH keys for private repositories
5. **Memory Issues**: Increase allocation for Ghost mode

### Debug Commands
```bash
# Check job status
nomad job status helen-[namespace]

# Inspect allocation
nomad alloc status [alloc-id]

# View Consul service
consul catalog services | grep helen

# Check Hecate routes
eos read hecate routes | grep helen
```

## Future Enhancements

1. **Multi-site Support**: Deploy multiple Helen instances
2. **Theme Management**: Automated theme deployment
3. **Plugin System**: Ghost plugin management
4. **CDN Integration**: Static asset CDN support
5. **Advanced Caching**: Redis/Memcached integration