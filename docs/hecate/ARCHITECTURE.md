# Hecate Two-Layer Reverse Proxy Architecture

## Overview

EOS uses Hecate as a two-layer reverse proxy architecture that separates public-facing infrastructure from local workloads.

## Architecture Layers

### Layer 1: Frontend (Hetzner Cloud)
**Location**: Hetzner Cloud Infrastructure  
**Purpose**: Public-facing entry point, SSL termination, authentication, DNS management

**Components:**
- **Caddy**: Primary HTTP/HTTPS reverse proxy with automatic SSL certificate management
- **Authentik**: Identity provider for authentication and authorization (SSO/SAML/OAuth2)
- **Hetzner DNS**: Automatic domain management and DNS record creation
- **Load Balancing**: Distributes traffic across multiple backend endpoints

### Layer 2: Backend (Local Infrastructure)
**Location**: Local/On-premises infrastructure  
**Purpose**: Service-specific proxy, load balancing, health checks, service isolation

**Components:**
- **Nginx**: Local reverse proxy containers deployed with each service
- **Nomad**: Container orchestration for local workloads
- **Consul**: Service discovery for backend services
- **Vault**: Secret management for service credentials

## Traffic Flow

```
Internet → Hetzner Cloud (Caddy + Authentik) → Local Infrastructure (Nginx + Service)
```

1. **External Request**: User accesses `service.domain.com`
2. **Cloud Layer**: Hetzner DNS routes to Caddy
3. **Authentication**: Authentik handles SSO/authentication if required
4. **SSL Termination**: Caddy handles SSL certificates and HTTPS
5. **Backend Routing**: Caddy proxies to local nginx container
6. **Service Proxy**: Local nginx routes to actual service via Consul discovery
7. **Response**: Response flows back through the same path

## Service Integration Pattern

### For New Services (e.g., n8n):

1. **Deploy Local Stack**:
   - Service container (n8n)
   - Local nginx container for service-specific routing
   - Register services with Consul for discovery

2. **Configure Local Proxy**:
   - nginx proxies external traffic to `service.service.consul:port`
   - Health checks and service-specific routing rules
   - Load balancing across service instances

3. **Register with Hecate Frontend**:
   - Create route in Hetzner Cloud Caddy
   - Configure Authentik authentication policies
   - Set up DNS records via Hetzner provider

4. **Benefits**:
   - Service isolation at local layer
   - Centralized authentication and SSL at cloud layer
   - Automatic DNS and certificate management
   - Security boundary between public and private infrastructure

## Implementation Details

### Local Nginx Configuration
```nginx
upstream service_backend {
    server service.service.consul:8147;
}

server {
    listen 80;
    location / {
        proxy_pass http://service_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    location /health {
        proxy_pass http://service_backend/healthz;
    }
}
```

### Hecate Route Registration
```go
route := &hecate.Route{
    Domain: "service.domain.com",
    Upstream: &hecate.Upstream{
        URL: "http://local-nginx-container:80",
    },
    AuthPolicy: &hecate.AuthPolicy{
        Provider: "authentik",
        Groups: []string{"service-users"},
    },
}
```

## Security Considerations

- **Network Isolation**: Local services not directly exposed to internet
- **Authentication Centralization**: All auth handled at cloud layer
- **SSL Termination**: Certificates managed centrally by Caddy
- **Service Discovery**: Internal routing via Consul, external via DNS
- **Audit Trail**: All access logged through Authentik and Caddy

## Monitoring and Health Checks

- **Cloud Layer**: Caddy health checks to local nginx
- **Local Layer**: nginx health checks to actual services
- **Service Discovery**: Consul health checks for service availability
- **Metrics**: Prometheus metrics from both layers

## Disaster Recovery

- **Cloud Failover**: Multiple Hetzner regions for Caddy/Authentik
- **Local Redundancy**: Multiple nginx instances per service
- **Service Scaling**: Nomad handles local service scaling
- **DNS Failover**: Hetzner DNS with health-based routing

## Future Enhancements

- **Multi-region**: Extend to multiple local infrastructure regions
- **Edge Caching**: Add CDN layer in front of Hetzner Cloud
- **Advanced Auth**: Enhanced Authentik policies and MFA requirements
- **Service Mesh**: Consider Istio/Linkerd for advanced service networking
