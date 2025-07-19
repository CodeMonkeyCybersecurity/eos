# Infrastructure Sizing Package

*Last Updated: 2025-01-19*

The `sizing` package provides comprehensive infrastructure sizing calculations for Eos deployments. It helps determine the optimal number of nodes, resource allocations, and service placements based on **documented, researched requirements** and workload characteristics.

## NEW: Systematic Requirements Calculator V2

The package now includes a **systematic, evidence-based calculator** that replaces the previous "finger in the air" approach with documented requirements from official sources, community benchmarks, and measured data.

### Key Features of V2:
- **Documented Requirements Database**: All component requirements are researched and referenced
- **Calculation Transparency**: Shows exactly how requirements are calculated step-by-step
- **Source Attribution**: Every requirement includes references to official documentation
- **Dependency Bundling**: Related services are bundled to avoid double-counting (e.g., Authentik includes PostgreSQL + Redis)
- **Hecate Integration**: Pre-configured profiles for common Hecate deployments
- **Extensible Framework**: Easy to add new services and deployment profiles

### Dependency Bundling Strategy

To avoid inflated requirements from double-counting dependencies, the sizing system bundles related services:

- **`authentik_sso`**: Includes Authentik application (2GB RAM, official minimum) + PostgreSQL database (1.5GB RAM) + Redis cache (0.5GB RAM) = **4GB total**
- **`consul_cluster`**: Includes all Consul services and dependencies in a single calculation
- **`vault_cluster`**: Includes Vault server and backend storage requirements

This prevents the common mistake of sizing PostgreSQL and Redis as standalone enterprise services when they're actually lightweight dependencies for a specific application.

## Features

- **Service-based sizing**: Pre-defined sizing profiles for common services (web servers, databases, caches, etc.)
- **Workload profiles**: Small, medium, and large workload templates
- **Environment-aware**: Different configurations for development, staging, and production
- **Cost estimation**: Basic cost calculations for different cloud providers
- **Validation**: Runtime validation of infrastructure against calculated requirements
- **Custom services**: Support for defining custom service requirements

## Usage

## Quick Start: Hecate Sizing

For Hecate deployments, use the pre-configured profiles:

```go
import (
    "github.com/CodeMonkeyCybersecurity/eos/pkg/sizing"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func calculateHecateRequirements(rc *eos_io.RuntimeContext) error {
    // Calculate requirements for small production Hecate deployment
    breakdown, err := sizing.CalculateHecateRequirements(rc, "small_production")
    if err != nil {
        return err
    }
    
    // Generate human-readable report
    report, err := sizing.GenerateHecateRecommendationReport(rc, "small_production")
    if err != nil {
        return err
    }
    
    logger.Info("Hecate requirements calculated",
        "cpu_cores", breakdown.FinalRequirements.CPU,
        "memory_gb", breakdown.FinalRequirements.Memory,
        "recommended_nodes", breakdown.NodeRecommendation.RecommendedNodes)
    
    return nil
}
```

Available Hecate profiles:
- `development`: Single-node development (10 users)
- `small_production`: Small production (50 users) 
- `medium_production`: Medium production (200 users)
- `large_production`: Large production (500+ users, includes HashiCorp stack)

## Systematic Calculator V2

For custom deployments or other services, use the systematic calculator:

```go
func calculateCustomRequirements(rc *eos_io.RuntimeContext) error {
    // Create calculator for production environment
    calc := sizing.NewCalculatorV2(sizing.WorkloadMedium, "production")
    
    // Add components with documented requirements
    calc.AddComponent("ubuntu_server_24.04")
    calc.AddComponent("postgresql_16")
    calc.AddComponent("redis_7")
    
    // Define workload characteristics
    workload := sizing.WorkloadCharacteristics{
        ConcurrentUsers:   100,
        RequestsPerSecond: 50,
        DataGrowthGB:      25.0,
        PeakMultiplier:    2.5,
        Type:             sizing.WorkloadMedium,
    }
    
    // Calculate with full breakdown
    breakdown, err := calc.Calculate(rc, workload)
    if err != nil {
        return err
    }
    
    // Get human-readable report showing calculation steps
    report := calc.GenerateHumanReadableReport()
    fmt.Println(report)
    
    return nil
}
```

### Integration with Eos Create Commands (Original)

The easiest way to add sizing checks to your create commands is using the `RunWithSizingChecks` wrapper:

```go
// In cmd/create/nomad.go
func runCreateNomad(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    config := parseNomadConfig(cmd)
    
    // Wrap your deployment with automatic sizing checks
    return sizing.RunWithSizingChecks(rc, "nomad", func(rc *eos_io.RuntimeContext) error {
        // Your existing deployment logic remains unchanged
        if err := nomad.Install(rc, config); err != nil {
            return err
        }
        if err := nomad.Configure(rc, config); err != nil {
            return err
        }
        return nomad.Verify(rc, config)
    })
}
```

This automatically:
- Performs preflight checks to validate system resources
- Prompts user if resources are insufficient
- Executes deployment if approved
- Runs postflight validation to verify service health

For custom services, register a mapping:

```go
sizing.RegisterServiceMapping("myapp", sizing.CreateServiceMapping(
    sizing.ServiceTypeWebServer,
    sizing.WithWorkloadProfile(sizing.WorkloadProfile{
        Name:              "API Gateway",
        ConcurrentUsers:   5000,
        RequestsPerSecond: 1000,
    }),
    sizing.WithRelatedServices(
        sizing.ServiceTypeDatabase,
        sizing.ServiceTypeCache,
    ),
))
```

### Basic Sizing Calculation

```go
import (
    "github.com/CodeMonkeyCybersecurity/eos/pkg/sizing"
    "github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
)

func calculateInfrastructureSize(rc *eos_io.RuntimeContext) error {
    // Select environment and workload profile
    config := sizing.EnvironmentConfigs["production"]
    workload := sizing.DefaultWorkloadProfiles["medium"]
    
    // Create calculator
    calc := sizing.NewCalculator(config, workload)
    
    // Add services
    calc.AddService(sizing.ServiceTypeWebServer)
    calc.AddService(sizing.ServiceTypeDatabase)
    calc.AddService(sizing.ServiceTypeCache)
    
    // Calculate requirements
    result, err := calc.Calculate(rc)
    if err != nil {
        return err
    }
    
    // Use the results
    logger.Info("Infrastructure requirements",
        "total_cpu_cores", result.TotalCPUCores,
        "total_memory_gb", result.TotalMemoryGB,
        "recommended_nodes", result.NodeCount)
    
    return nil
}
```

### Custom Service Definition

```go
// Define a custom service
customService := sizing.ServiceDefinition{
    Name: "AI Service",
    Type: sizing.ServiceType("ai_service"),
    BaseRequirements: sizing.ResourceRequirements{
        CPU:    sizing.CPURequirements{Cores: 16, Type: "compute"},
        Memory: sizing.MemoryRequirements{GB: 64, Type: "high-performance"},
        Disk:   sizing.DiskRequirements{GB: 500, Type: "nvme", IOPS: 30000},
    },
    ScalingFactor:    0.01,
    LoadFactor:       2.0,
    RedundancyFactor: 2,
}

calc.AddCustomService(customService)
calc.AddService(sizing.ServiceType("ai_service"))
```

### Validation

```go
// Create validator from sizing results
validator := sizing.NewValidator(result)

// Validate a node configuration
node := sizing.NodeSpecification{
    CPUCores:    32,
    MemoryGB:    128,
    DiskGB:      2000,
    DiskType:    "nvme",
    NetworkGbps: 40,
}

errors, err := validator.ValidateNodeCapacity(rc, node)
if len(errors) > 0 {
    for _, e := range errors {
        logger.Warn("Validation error", "field", e.Field, "message", e.Message)
    }
}

// Generate human-readable report
report := validator.GenerateReport(rc)
fmt.Println(report)
```

## Service Types

The package includes pre-defined sizing for:

- **Web Server**: HTTP/HTTPS servers (nginx, apache)
- **Database**: Relational and NoSQL databases
- **Cache**: In-memory caches (Redis, Memcached)
- **Queue**: Message queues (RabbitMQ, Kafka)
- **Worker**: Background job processors
- **Proxy**: Load balancers and reverse proxies
- **Monitoring**: Metrics and monitoring stacks
- **Logging**: Centralized logging systems
- **Storage**: Object/block storage services
- **Container**: Container runtimes (Docker)
- **Orchestrator**: Container orchestrators (Kubernetes, Nomad)
- **Vault**: Secret management systems

## Workload Profiles

### Small
- 100 concurrent users
- 10 requests/second
- 10 GB/month data growth
- 30-day retention

### Medium
- 1,000 concurrent users
- 100 requests/second
- 100 GB/month data growth
- 90-day retention

### Large
- 10,000 concurrent users
- 1,000 requests/second
- 1 TB/month data growth
- 365-day retention

## Environment Configurations

### Development
- 1.2x overprovision ratio
- 1.1x growth buffer
- Smaller node limits

### Staging
- 1.5x overprovision ratio
- 1.3x growth buffer
- Medium node limits

### Production
- 2.0x overprovision ratio
- 1.5x growth buffer
- Large node limits
- Minimum 3 nodes for HA

## Integration with Eos

The sizing package can be integrated into Eos commands for:

1. **Pre-deployment validation**: Ensure infrastructure meets requirements before deployment
2. **Resource allocation**: Automatically configure resource limits based on sizing
3. **Scaling decisions**: Determine when to add nodes or upgrade resources
4. **Cost optimization**: Compare different configurations and providers

Example integration in a command:

```go
func runCreateInfrastructure(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    // Get sizing parameters from flags
    environment := cmd.Flag("environment").Value.String()
    workloadSize := cmd.Flag("workload-size").Value.String()
    
    // Calculate requirements
    config := sizing.EnvironmentConfigs[environment]
    workload := sizing.DefaultWorkloadProfiles[workloadSize]
    
    calc := sizing.NewCalculator(config, workload)
    // ... add services based on user selection
    
    result, err := calc.Calculate(rc)
    if err != nil {
        return err
    }
    
    // Use sizing results to provision infrastructure
    return provisionInfrastructure(rc, result)
}
```

## Best Practices

1. **Start with defaults**: Use the pre-defined service definitions and workload profiles as a starting point
2. **Validate assumptions**: The sizing calculations make assumptions about resource usage - validate with actual metrics
3. **Monitor and adjust**: Use the validator to check if your infrastructure still meets requirements as load changes
4. **Consider growth**: The growth buffer helps account for future expansion
5. **Test thoroughly**: Validate sizing calculations in staging before production

## Extending the Package

To add new service types:

1. Add the service type constant to `types.go`
2. Add the service definition to `ServiceDefinitions` map
3. Update the scaling calculation logic if needed
4. Add appropriate tests

To add new providers for cost estimation:

1. Update the cost calculation logic in `estimateCosts()`
2. Add provider-specific instance type mappings
3. Consider regional pricing variations