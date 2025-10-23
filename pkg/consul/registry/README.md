## Consul Service Registry

*Last Updated: 2025-10-23*

Programmatic service discovery and registration API for Consul, replacing file-based service configuration with SDK-based dynamic operations.

## Overview

The ServiceRegistry provides a comprehensive API for:
- **Service Registration**: Programmatically register services with health checks
- **Service Discovery**: Find service instances by name, tag, health status
- **Health Management**: Register, update, and monitor health checks
- **Service Watching**: Real-time notifications of service changes
- **Metadata Management**: Query and update service metadata

## Architecture

```
ServiceRegistry Interface
├── ConsulServiceRegistry (Consul API implementation)
│   ├── Service Registration (RegisterService, DeregisterService, UpdateService)
│   ├── Service Discovery (DiscoverService, DiscoverHealthyServices, WatchService)
│   ├── Health Checks (RegisterHealthCheck, UpdateHealthCheckStatus)
│   └── Metadata (GetServiceMetadata, UpdateServiceMetadata)
└── Mock implementations for testing
```

## Quick Start

### 1. Create a Service Registry

```go
import (
    "context"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/consul/registry"
)

ctx := context.Background()
reg, err := registry.NewServiceRegistry(ctx, "shared.GetInternalHostname:8500")
if err != nil {
    log.Fatal(err)
}
```

### 2. Register a Service

```go
service := &registry.ServiceRegistration{
    ID:      "vault-vhost5",
    Name:    "vault",
    Address: "192.168.1.100",
    Port:    8200,
    Tags:    []string{"active", "tls", "primary"},
    Meta: map[string]string{
        "version":     "1.15.0",
        "environment": "production",
    },
    Check: &registry.HealthCheck{
        ID:            "vault-health",
        Name:          "Vault HTTPS Health",
        Type:          registry.HealthCheckHTTPS,
        HTTP:          "https://192.168.1.100:8200/v1/sys/health",
        Interval:      10 * time.Second,
        Timeout:       5 * time.Second,
        TLSSkipVerify: true,
    },
}

err := reg.RegisterService(ctx, service)
if err != nil {
    log.Fatal(err)
}
```

### 3. Discover Services

```go
// Find all healthy Vault instances
instances, err := reg.DiscoverHealthyServices(ctx, "vault")
if err != nil {
    log.Fatal(err)
}

for _, instance := range instances {
    fmt.Printf("Vault at %s:%d (health: %s)\n",
        instance.Address, instance.Port, instance.Health)
}
```

### 4. Watch for Service Changes

```go
callback := func(instances []*registry.ServiceInstance, err error) {
    if err != nil {
        log.Printf("Watch error: %v\n", err)
        return
    }

    log.Printf("Service changed: %d instances\n", len(instances))
    for _, inst := range instances {
        log.Printf("  - %s:%d (health: %s)\n",
            inst.Address, inst.Port, inst.Health)
    }
}

err := reg.WatchService(ctx, "vault", callback)
if err != nil {
    log.Fatal(err)
}
```

## Advanced Usage

### Health Check Types

```go
// HTTP/HTTPS Check
check := &registry.HealthCheck{
    ID:       "api-health",
    Name:     "API Health Check",
    Type:     registry.HealthCheckHTTP,
    HTTP:     "http://localhost:8080/health",
    Interval: 10 * time.Second,
    Timeout:  5 * time.Second,
    Header: map[string][]string{
        "Authorization": {"Bearer token"},
        "X-API-Key":     {"my-api-key"},
    },
}

// TCP Check
tcpCheck := &registry.HealthCheck{
    ID:       "db-tcp",
    Name:     "Database TCP Check",
    Type:     registry.HealthCheckTCP,
    TCP:      "localhost:5432",
    Interval: 10 * time.Second,
    Timeout:  3 * time.Second,
}

// TTL Check (service reports its own health)
ttlCheck := &registry.HealthCheck{
    ID:       "app-ttl",
    Name:     "Application TTL",
    Type:     registry.HealthCheckTTL,
    Interval: 30 * time.Second,
}

// gRPC Check
grpcCheck := &registry.HealthCheck{
    ID:       "grpc-health",
    Name:     "gRPC Health",
    Type:     registry.HealthCheckGRPC,
    GRPC:     "localhost:50051/health",
    Interval: 10 * time.Second,
}
```

### Filtering and Queries

```go
// Find services with specific tags
filter := &registry.ServiceFilter{
    Tags:   []string{"production", "primary"},
    Health: registry.HealthPassing,
    Meta: map[string]string{
        "version": "1.15.0",
    },
}

instances, err := reg.ListServices(ctx, filter)

// Query by tag (convenience method)
prodServices, err := reg.QueryServicesByTag(ctx, "production")
```

### Service Weights (Load Balancing)

```go
service := &registry.ServiceRegistration{
    ID:   "web-1",
    Name: "web",
    Port: 8080,
    Weights: &registry.ServiceWeights{
        Passing: 10,  // Weight when healthy
        Warning: 1,   // Weight when degraded
    },
}
```

### Multiple Health Checks

```go
service := &registry.ServiceRegistration{
    ID:   "api-server",
    Name: "api",
    Checks: []*registry.HealthCheck{
        {
            ID:       "api-http",
            Name:     "API HTTP",
            Type:     registry.HealthCheckHTTP,
            HTTP:     "http://localhost:8080/health",
            Interval: 10 * time.Second,
        },
        {
            ID:       "api-db",
            Name:     "Database Connection",
            Type:     registry.HealthCheckTCP,
            TCP:      "localhost:5432",
            Interval: 30 * time.Second,
        },
    },
}
```

## Migration from File-Based Registration

### Before (File-Based)
```go
// pkg/consul/vault/service.go - OLD
serviceConfig := `{
  "service": {
    "name": "vault",
    "port": 8200,
    "check": {
      "http": "https://localhost:8200/v1/sys/health",
      "interval": "10s"
    }
  }
}`

os.WriteFile("/etc/consul.d/vault-service.json", []byte(serviceConfig), 0640)
// Requires Consul reload
```

### After (SDK-Based)
```go
// Using ServiceRegistry - NEW
service := &registry.ServiceRegistration{
    Name: "vault",
    Port: 8200,
    Check: &registry.HealthCheck{
        Type:     registry.HealthCheckHTTPS,
        HTTP:     "https://localhost:8200/v1/sys/health",
        Interval: 10 * time.Second,
    },
}

reg.RegisterService(ctx, service)
// Immediate, no reload required
```

## Benefits Over File-Based Approach

| Feature | File-Based | SDK-Based (This API) |
|---------|------------|---------------------|
| **Dynamic Updates** | Requires Consul reload | Immediate |
| **Error Handling** | Silent failures | Explicit errors with context |
| **Verification** | Manual | Automatic EVALUATE phase |
| **Service Discovery** | Manual JSON parsing | Type-safe Go structs |
| **Health Monitoring** | Poll files | Real-time callbacks |
| **Testing** | Difficult (requires filesystem) | Easy (mockable interface) |
| **Type Safety** | None (JSON strings) | Full Go type checking |

## Testing

The interface is fully mockable for testing:

```go
type MockRegistry struct {
    Services map[string]*ServiceRegistration
}

func (m *MockRegistry) RegisterService(ctx context.Context, service *ServiceRegistration) error {
    m.Services[service.ID] = service
    return nil
}

func (m *MockRegistry) DiscoverService(ctx context.Context, name string, opts *DiscoveryOptions) ([]*ServiceInstance, error) {
    var instances []*ServiceInstance
    for _, svc := range m.Services {
        if svc.Name == name {
            instances = append(instances, &ServiceInstance{
                ID:      svc.ID,
                Name:    svc.Name,
                Address: svc.Address,
                Port:    svc.Port,
                Health:  HealthPassing,
            })
        }
    }
    return instances, nil
}
```

## Integration with Eos

### Vault Registration (Updated)

Replace `pkg/consul/vault/service.go`:

```go
func RegisterVaultWithConsul(rc *eos_io.RuntimeContext, vaultAddr string) error {
    reg, err := registry.NewServiceRegistry(rc.Ctx, "shared.GetInternalHostname:8500")
    if err != nil {
        return err
    }

    hostname := eos_unix.GetInternalHostname()

    service := &registry.ServiceRegistration{
        ID:      fmt.Sprintf("vault-%s", hostname),
        Name:    "vault",
        Address: extractHost(vaultAddr),
        Port:    extractPort(vaultAddr),
        Tags:    []string{"active", "tls", "primary", "eos-managed"},
        Meta: map[string]string{
            "version":      getVaultVersion(),
            "storage_type": "file",
            "eos_managed":  "true",
        },
        Check: &registry.HealthCheck{
            ID:                     "vault-health",
            Name:                   "Vault HTTPS Health",
            Type:                   registry.HealthCheckHTTPS,
            HTTP:                   fmt.Sprintf("%s/v1/sys/health?standbyok=true", vaultAddr),
            Interval:               10 * time.Second,
            Timeout:                5 * time.Second,
            TLSSkipVerify:          true,
            SuccessBeforePassing:   2,
            FailuresBeforeCritical: 3,
        },
        Weights: &registry.ServiceWeights{
            Passing: 10,
            Warning: 1,
        },
    }

    return reg.RegisterService(rc.Ctx, service)
}
```

## Error Handling

All operations follow ASSESS → INTERVENE → EVALUATE pattern with comprehensive error handling:

```go
err := reg.RegisterService(ctx, service)
if err != nil {
    // Error includes context about what failed
    log.Printf("Registration failed: %v\n", err)
    // Errors:
    // - "service name is required"
    // - "failed to register service vault-vhost5: connection refused"
    // - "service vault-vhost5 not found after registration" (EVALUATE failed)
}
```

## Performance Considerations

- **Blocking Queries**: Service watches use Consul's blocking query API for efficient change notifications
- **Connection Pooling**: Consul client maintains HTTP connection pool
- **Caching**: Consul client caches agent self-data
- **Batch Operations**: Use `ListServices` with filters instead of multiple `DiscoverService` calls

## Troubleshooting

### Service Not Appearing

```go
// Verify registration
services, _ := reg.ListServices(ctx, &registry.ServiceFilter{
    Name: "vault",
})
log.Printf("Found %d vault instances\n", len(services))

// Check health status
for _, svc := range services {
    log.Printf("Service %s: health=%s\n", svc.ID, svc.Health)
    for _, check := range svc.Checks {
        log.Printf("  Check %s: %s - %s\n", check.Name, check.Status, check.Output)
    }
}
```

### Health Check Failing

```go
// Get detailed check status
result, err := reg.GetHealthCheckStatus(ctx, "vault-health")
if err == nil {
    log.Printf("Check status: %s\n", result.Status)
    log.Printf("Check output: %s\n", result.Output)
}
```

## Future Enhancements

- [ ] Prepared queries support
- [ ] Connect/service mesh integration
- [ ] ACL token management in registry
- [ ] Service intentions API
- [ ] Catalog synchronization
- [ ] Multi-datacenter federation support
