# EOS Two-Layer Architecture Audit Report

## Executive Summary

This audit examines the EOS codebase to identify services that should follow the standardized Hecate two-layer reverse proxy architecture. The audit reveals several services with inconsistent proxy patterns that should be standardized.

## Architecture Standard

**Two-Layer Pattern:**
- **Layer 1 (Frontend - Hetzner Cloud)**: Caddy + Authentik + Hetzner DNS
- **Layer 2 (Backend - Local)**: nginx + service + Consul discovery

## Audit Findings

### ✅ Compliant Services

#### 1. n8n (`pkg/n8n/`)
- **Status**: ✅ COMPLIANT (Recently updated)
- **Pattern**: Deploys local nginx → registers with Hecate frontend
- **Architecture**: Two-layer with proper separation
- **Notes**: Reference implementation for other services

### 🔄 Partially Compliant Services

#### 2. Helen (`pkg/helen/`)
- **Status**: 🔄 PARTIAL - Uses nginx but no Hecate integration
- **Current**: Deploys nginx via Nomad with Consul service discovery
- **Missing**: Hecate frontend registration
- **Recommendation**: Add Hecate route registration to complete two-layer pattern

#### 3. Nomad Ingress (`cmd/create/nomad.go`)
- **Status**: 🔄 PARTIAL - Has ingress concept but standalone
- **Current**: Deploys Caddy + nginx via Nomad jobs
- **Issue**: Standalone deployment, not integrated with Hecate
- **Recommendation**: Integrate with existing Hecate stack instead of standalone

### ❌ Non-Compliant Services

#### 4. Hera/Authentik (`cmd/create/hera.go`)
- **Status**: ❌ NON-COMPLIANT - Uses docker-compose directly
- **Current**: Direct docker-compose deployment with port exposure
- **Issue**: No reverse proxy layer, direct port exposure (9000)
- **Recommendation**: Add nginx proxy layer + Hecate integration

#### 5. Traefik Infrastructure (`pkg/deploy/traefik.go`)
- **Status**: ❌ NON-COMPLIANT - Standalone reverse proxy
- **Current**: Standalone Traefik deployment
- **Issue**: Conflicts with Hecate architecture
- **Recommendation**: Deprecate in favor of Hecate or integrate as backend

#### 6. ClusterFuzz (`pkg/clusterfuzz/nomad/jobs.go`)
- **Status**: ❌ NON-COMPLIANT - No reverse proxy
- **Current**: Direct service exposure via Nomad
- **Issue**: No proxy layer for web interface
- **Recommendation**: Add nginx proxy + Hecate integration

### 🚫 Deprecated Services

#### 7. K3s Caddy Nginx (`cmd/create/k3s_caddy_nginx.go`)
- **Status**: 🚫 DEPRECATED - Already marked deprecated
- **Current**: Marked deprecated, recommends nomad-ingress
- **Action**: No changes needed, properly deprecated

## Services Requiring Updates

### High Priority

1. **Hera/Authentik** - Critical auth service needs proper proxy
2. **Helen** - Web interface service, easy to update
3. **ClusterFuzz** - Security testing tool needs secure access

### Medium Priority

4. **Nomad Ingress** - Consolidate with Hecate
5. **Traefik Infrastructure** - Deprecate or integrate

## Standardization Recommendations

### 1. Service Template Pattern
```go
// Standard pattern for all web services
func (m *Manager) Deploy(ctx context.Context) error {
    // Deploy service containers
    if err := m.deployService(ctx); err != nil {
        return err
    }
    
    // Deploy local nginx proxy (Layer 2)
    if err := m.deployNginxProxy(ctx); err != nil {
        return err
    }
    
    // Register with Hecate frontend (Layer 1)
    if err := m.registerHecateRoute(ctx); err != nil {
        return err
    }
    
    return nil
}
```

### 2. Required Components
- Local nginx container via Nomad
- Consul service registration
- Hecate route registration
- Health checks at both layers

### 3. Configuration Standards
- Use shared port management (`pkg/shared/ports.go`)
- Standard nginx configuration templates
- Consistent service naming conventions
- Unified authentication via Authentik

## Implementation Plan

### Phase 1: Update Existing Services
1. Helen - Add Hecate integration
2. Hera - Add nginx proxy layer
3. ClusterFuzz - Add reverse proxy

### Phase 2: Consolidate Infrastructure
1. Deprecate standalone Traefik
2. Integrate Nomad ingress with Hecate
3. Update documentation

### Phase 3: Enforce Standards
1. Create service deployment templates
2. Add architecture compliance checks
3. Update development guidelines

## Security Benefits

- **Centralized Authentication**: All services use Authentik
- **SSL Termination**: Managed by Caddy at cloud layer
- **Network Isolation**: Services not directly exposed
- **Audit Trail**: Centralized logging through Hecate
- **Rate Limiting**: Applied at cloud layer

## Operational Benefits

- **Simplified DNS**: Managed by Hetzner integration
- **Certificate Management**: Automatic via Caddy
- **Load Balancing**: Consistent across all services
- **Health Monitoring**: Standardized health checks
- **Service Discovery**: Consul-based routing

## Next Steps

1. Update non-compliant services following n8n pattern
2. Create shared nginx configuration templates
3. Implement Hecate integration helpers
4. Update service deployment documentation
5. Add architecture compliance testing
