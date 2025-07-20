# User Experience Abstraction Implementation

*Last Updated: 2025-01-20*

## Overview

This document describes the implemented abstracted user experience for Eos, where users interact with a consistent `eos create X` interface regardless of the underlying orchestration technology (SaltStack for infrastructure, Nomad for applications).

## Implemented Architecture

### Transparent Dual-Layer Deployment

Users never need to understand or manage the underlying complexity:

```bash
# User sees this simple interface
eos create grafana --admin-password secret123

# Behind the scenes:
# 1. Determines this is an application service (not infrastructure)
# 2. Ensures Nomad is running (auto-installs if needed)
# 3. Generates Nomad job from template
# 4. Deploys via Nomad with service discovery
# 5. Reports success with access URLs
```

### Service Classification (Transparent to Users)

The system automatically determines the deployment method:

#### Infrastructure Services → SaltStack
- **consul, vault, nomad, saltstack** - Core orchestration
- **fail2ban, trivy, osquery** - Security and monitoring
- **docker** - Container runtime

#### Application Services → Nomad
- **grafana, jenkins, nextcloud** - User applications
- **postgres, redis, mongodb** - Database services
- **mattermost, gitlab** - Collaboration tools

## Implementation Components

### 1. Nomad Job Templates (`/opt/eos/nomad/jobs/`)

Pre-built, parameterized job templates for common services:

```hcl
# Example: grafana.nomad
job "grafana" {
  datacenters = [var.datacenter]
  
  group "grafana" {
    task "grafana" {
      driver = "docker"
      config {
        image = "grafana/grafana:latest"
        ports = ["http"]
      }
      
      service {
        name = "grafana"
        port = "http"
        tags = ["monitoring", "eos-managed"]
        
        check {
          type = "http"
          path = "/api/health"
          interval = "10s"
        }
      }
    }
  }
}
```

### 2. Nomad Orchestrator Package (`/opt/eos/pkg/nomad_orchestrator/`)

Shared framework that handles:
- ✅ **Prerequisite checking** (Nomad availability)
- ✅ **Template rendering** with user configuration
- ✅ **Job deployment** via `nomad job run`
- ✅ **Health verification** and status reporting
- ✅ **Service discovery** registration with Consul

### 3. Abstracted Command Implementation

Example: `/opt/eos/cmd/create/grafana.go`

```go
func runCreateGrafana(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    // Get user configuration from flags
    adminPassword, _ := cmd.Flags().GetString("admin-password")
    port, _ := cmd.Flags().GetInt("port")
    
    // Create orchestrator (abstracts Nomad complexity)
    orchestrator := nomad_orchestrator.NewOrchestrator(rc)
    
    // Build job configuration
    config := &nomad_orchestrator.JobConfig{
        ServiceName: "grafana",
        JobTemplate: "grafana.nomad",
        Port:        port,
        Variables: map[string]interface{}{
            "admin_password": adminPassword,
        },
    }
    
    // Deploy (handles all complexity)
    result, err := orchestrator.DeployJob(config)
    
    // Report success
    logger.Info("Grafana is now available",
        zap.String("web_ui", result.URL),
        zap.String("username", "admin"))
    
    return nil
}
```

## User Experience Benefits

### Before (Complex)
```bash
# User had to understand Docker Compose
eos create grafana --docker-compose
# or understand different deployment methods
eos create grafana --method docker --version 10.2.0 --interactive

# Different interfaces for different services
eos create consul --salt-state hashicorp.consul
eos create grafana --docker-compose monitoring/grafana.yml
```

### After (Abstracted)
```bash
# Consistent interface for all services
eos create consul        # Infrastructure → SaltStack (automatic)
eos create grafana       # Application → Nomad (automatic)
eos create jenkins       # Application → Nomad (automatic)
eos create fail2ban      # Infrastructure → SaltStack (automatic)

# Same flag patterns work everywhere
eos create grafana --port 3000 --admin-password secret
eos create jenkins --port 8080 --admin-password secret
```

## Operational Benefits

### For Infrastructure Services (SaltStack)
- **Idempotent** installations
- **Configuration management** via pillar data
- **System service** integration (systemd)
- **Host-level** security and monitoring

### For Application Services (Nomad)
- **Container lifecycle** management
- **Service discovery** via Consul
- **Health monitoring** and recovery
- **Resource allocation** and scheduling
- **Service mesh** ready (Consul Connect)

### Unified Management
- **Single service registry** (Consul)
- **Consistent logging** (structured logs)
- **Unified monitoring** (all services visible)
- **Predictable networking** (CNI + service mesh)

## Scaling Path

### Single Node → Multi-Node Cluster
The abstraction enables seamless scaling:

```bash
# Single node deployment
eos create grafana

# Later: Add worker nodes
eos create nomad --mode client --join server1.example.com

# Same grafana deployment now scales across cluster
# No user command changes required
```

### Development → Production
Configuration scales with environment:

```bash
# Development
eos create grafana --datacenter dev

# Production  
eos create grafana --datacenter production --admin-password $VAULT_SECRET
```

## Implementation Status

### ✅ Completed
- [x] Architecture documentation updated
- [x] SaltStack + Nomad integration patterns defined
- [x] Nomad orchestrator framework implemented
- [x] Grafana command converted to abstracted pattern
- [x] Job templates created (Grafana, Jenkins)
- [x] User experience abstraction framework

### 📋 Next Steps
1. **Convert remaining application services** (Jenkins, Nextcloud, Mattermost)
2. **Migrate infrastructure services** (fail2ban, trivy, osquery) to SaltStack
3. **Add volume management** for persistent data
4. **Implement service scaling** commands
5. **Add multi-node cluster** support

## Example User Workflows

### Deploy Monitoring Stack
```bash
eos create saltstack     # Base orchestration
eos create consul        # Service discovery  
eos create nomad         # Container orchestrator
eos create grafana       # Monitoring dashboard
```

### Deploy CI/CD Pipeline
```bash
eos create jenkins       # CI/CD platform
eos create postgres      # Database for Jenkins
eos create redis         # Cache for builds
```

### Deploy Collaboration Platform
```bash
eos create nextcloud     # File sharing
eos create mattermost    # Team chat  
eos create postgres      # Shared database
```

All commands use the same simple interface while managing complex orchestration automatically.