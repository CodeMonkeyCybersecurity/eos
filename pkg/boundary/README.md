# Boundary  API Implementation

*Last Updated: 2025-01-23*

This package provides a Go client for managing HashiCorp Boundary deployments using the  REST API, enabling programmatic control of Boundary infrastructure without shell execution.

## Features

- **Complete Boundary Management**: Create, delete, and monitor Boundary controllers and workers
- ** API Integration**: Uses existing  REST API client for reliable communication
- **Role-based Configuration**: Supports controller, worker, and dev (combined) roles
- **Database Integration**: Automatic PostgreSQL setup for controllers
- **KMS Support**: Configurable Key Management Service integration
- **Real-time Progress**: Optional streaming of installation/removal progress
- **Idempotent Operations**: Safe to run multiple times without side effects
- **Comprehensive Status**: Detailed status reporting across all minions

## Architecture

### Boundary Components

- **Controllers**: Manage the Boundary cluster, handle API requests, store configuration in PostgreSQL
- **Workers**: Proxy connections between users and targets, register with controllers
- **Database**: PostgreSQL backend for storing Boundary configuration and session data

### Integration Points

- ** States**: Uses `hashicorp.boundary` and `hashicorp.boundary_remove`  states
- **Service Discovery**: Integrates with Consul for service registration
- **Secrets Management**: Uses Vault for secure credential storage
- **TLS/PKI**: Automatic certificate management for secure communication

## Configuration

### Environment Variables

```bash
export _API_URL="https://-master.example.com:8080"
export _API_USER="eos-service"
export _API_PASSWORD="secure-password"
export _API_INSECURE="false"  # Set to true for self-signed certs in dev
```

### Boundary Configuration

The Boundary manager accepts comprehensive configuration through the `Config` struct:

```go
config := &boundary.Config{
    // Role: "controller", "worker", or "dev"
    Role:        "controller",
    Version:     "0.15.0",
    ClusterName: "production",
    
    // Controller-specific
    DatabaseURL:       "postgresql://boundary:password@db.example.com/boundary",
    PublicClusterAddr: "boundary-controller.example.com:9201",
    PublicAddr:        "boundary-controller.example.com:9200",
    
    // Worker-specific
    InitialUpstreams: []string{
        "controller1.example.com:9201",
        "controller2.example.com:9201",
    },
    PublicProxyAddr: "boundary-worker.example.com:9202",
    
    // TLS Configuration
    TLSDisable:  false,
    TLSCertFile: "/etc/boundary/tls/cert.pem",
    TLSKeyFile:  "/etc/boundary/tls/key.pem",
    
    // KMS Configuration
    KMSType:   "aead",
    KMSKeyID:  "global_root",
    KMSRegion: "us-west-2",
}
```

## Usage Examples

### Creating a Boundary Controller

```go
// Create  client
Client, err := .NewClient(.ClientConfig{
    BaseURL:  "https://-master:8080",
    Username: "eos-service",
    Password: os.Getenv("_API_PASSWORD"),
    Logger:   logger,
})
if err != nil {
    log.Fatal(err)
}

// Create Boundary manager
manager, err := boundary.NewManager(rc, Client)
if err != nil {
    log.Fatal(err)
}

// Create controller
err = manager.Create(ctx, &boundary.CreateOptions{
    Target: "boundary-controller-*",
    Config: &boundary.Config{
        Role:        "controller",
        Version:     "0.15.0",
        ClusterName: "production",
        DatabaseURL: "postgresql://boundary:password@db.example.com/boundary",
    },
    Force:        false,
    Clean:        false,
    StreamOutput: true,
})
```

### Creating a Boundary Worker

```go
err = manager.Create(ctx, &boundary.CreateOptions{
    Target: "boundary-worker-*",
    Config: &boundary.Config{
        Role:        "worker",
        Version:     "0.15.0",
        ClusterName: "production",
        InitialUpstreams: []string{
            "controller1.example.com:9201",
            "controller2.example.com:9201",
        },
        PublicProxyAddr: "boundary-worker.example.com:9202",
    },
    StreamOutput: true,
})
```

### Removing Boundary

```go
err = manager.Delete(ctx, &boundary.DeleteOptions{
    Target:      "boundary-*",
    ClusterName: "production",
    KeepData:    false,
    KeepConfig:  false,
    KeepUser:    false,
    Force:       true,
    StreamOutput: true,
})
```

## CLI Usage

### Installation

```bash
# Install Boundary controller
eos create boundary --role controller \
  --database-url "postgresql://boundary:password@db.example.com/boundary" \
  --version 0.15.0

# Install Boundary worker
eos create boundary --role worker \
  --upstream "controller1:9201,controller2:9201" \
  --public-proxy-addr "worker.example.com:9202"

# Install dev mode (controller + worker)
eos create boundary --role dev \
  --database-url "postgresql://boundary:password@localhost/boundary"

# Force reinstallation
eos create boundary --role controller --force

# Clean installation (removes all data)
eos create boundary --role controller --clean

# Stream installation progress
eos create boundary --role controller --stream
```

### Removal

```bash
# Remove Boundary with confirmation
eos delete boundary

# Force removal without confirmation
eos delete boundary --force

# Remove but keep data
eos delete boundary --keep-data

# Remove but preserve configuration
eos delete boundary --keep-config

# Stream removal progress
eos delete boundary --stream
```

##  State Integration

The implementation relies on  states that should be present on your  master:

### Required  States

1. **hashicorp.boundary** - Main installation and configuration state
2. **hashicorp.boundary_remove** - Removal and cleanup state

###  Data Structure

The manager generates  data in this format:

```yaml
boundary:
  cluster_name: production
  role: controller
  enabled: true
  version: 0.15.0
  
  # Controller-specific
  database_url: postgresql://boundary:password@db.example.com/boundary
  public_cluster_addr: boundary-controller.example.com:9201
  public_addr: boundary-controller.example.com:9200
  
  # Worker-specific
  initial_upstreams:
    - controller1.example.com:9201
    - controller2.example.com:9201
  public_proxy_addr: boundary-worker.example.com:9202
  
  # TLS configuration
  tls_disable: false
  tls_cert_file: /etc/boundary/tls/cert.pem
  tls_key_file: /etc/boundary/tls/key.pem
  
  # KMS configuration
  kms:
    type: aead
    key_id: global_root
    region: us-west-2
  
  # Installation options
  force: false
  clean: false
```

## Error Handling

The implementation provides detailed error information:

```go
err := manager.Create(ctx, opts)
if err != nil {
    // Errors include details about which minions failed
    // and what specific states caused the failure
    if strings.Contains(err.Error(), "database") {
        log.Printf("Database connection issue: %v", err)
    } else if strings.Contains(err.Error(), "timeout") {
        log.Printf("Operation timed out: %v", err)
    }
}
```

## Development and Testing

### Running Tests

```bash
go test -v ./pkg/boundary/...
```

### Mock  API

Tests include a mock  API server for testing without a real  installation:

```go
server := createMockAPI(t)
defer server.Close()

Client, err := .NewClient(.ClientConfig{
    BaseURL:  server.URL,
    Username: "test",
    Password: "test",
})
```

### Integration Testing

For integration testing with a real  master:

1. Set up test environment variables
2. Deploy test  states
3. Run integration tests:

```bash
_API_URL=https://test-:8080 \
_API_PASSWORD=test-password \
go test -tags=integration ./pkg/boundary/...
```

## Production Considerations

### Security

1. **Database Security**: Use strong passwords and TLS for PostgreSQL connections
2. **TLS Configuration**: Always use proper certificates in production
3. **KMS Integration**: Use cloud KMS services for production key management
4. **Network Security**: Secure communication between controllers and workers

### High Availability

1. **Multiple Controllers**: Deploy at least 3 controllers for HA
2. **Database HA**: Use PostgreSQL clustering or managed database services
3. **Load Balancing**: Use load balancers for controller API endpoints
4. **Geographic Distribution**: Deploy across availability zones

### Monitoring

1. **Health Checks**: Monitor Boundary service health
2. **Database Monitoring**: Monitor PostgreSQL connections and performance
3. **Log Aggregation**: Collect and analyze Boundary logs
4. **Metrics Collection**: Export Boundary metrics to monitoring systems

### Backup and Recovery

1. **Database Backups**: Regular PostgreSQL backups
2. **Configuration Backups**: Version control Boundary configurations
3. **Disaster Recovery**: Test recovery procedures regularly

## Troubleshooting

### Common Issues

1. **Database Connection Failures**
   - Verify PostgreSQL connectivity
   - Check firewall rules
   - Validate connection strings

2. **Worker Registration Issues**
   - Verify controller accessibility
   - Check upstream addresses
   - Validate TLS configuration

3. ** State Failures**
   - Check  minion connectivity
   - Verify state file availability
   - Review  master logs

### Debug Mode

Enable debug logging:

```bash
EOS_LOG_LEVEL=debug eos create boundary --role controller
```

### Manual Verification

```bash
# Check service status
systemctl status boundary

# Check logs
journalctl -u boundary -f

# Test database connectivity
boundary database migrate -config /etc/boundary/controller.hcl -dry-run

# List cluster members
boundary dev database-init -config /etc/boundary/controller.hcl
```

## Migration and Upgrades

### Version Upgrades

```bash
# Upgrade to new version
eos create boundary --role controller --version 0.16.0 --force
```

### Configuration Changes

```bash
# Update configuration
eos create boundary --role controller --force
```

## Contributing

### Adding Features

1. Extend the `Config` struct for new configuration options
2. Update the  data generation in `buildCreate`
3. Add corresponding CLI flags
4. Update tests and documentation

### Code Style

- Follow Go best practices
- Use structured logging with zap
- Add comprehensive error messages
- Include unit tests for new functionality

## License

This implementation follows the same license as the EOS project.