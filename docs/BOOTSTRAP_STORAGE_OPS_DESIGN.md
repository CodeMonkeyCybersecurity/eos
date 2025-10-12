# Bootstrap Storage Operations Integration

> **📝 Documentation has been moved inline with the code for better maintainability.**
> 
> The comprehensive bootstrap storage operations documentation is now embedded directly in the Go source files where the functionality is implemented. This ensures the documentation stays current with code changes and is immediately available to developers.

## Quick Reference

For detailed bootstrap storage operations documentation, see the inline comments in these files:

- **Cluster Detection**: `pkg/bootstrap/detector.go` - Cluster state detection and node discovery
- **Bootstrap Orchestrator**: `pkg/bootstrap/orchestrator.go` - Bootstrap orchestration and phase management
- **Storage Integration**: `pkg/storage/bootstrap_ops.go` - Storage operations during bootstrap
- **Role Assignment**: `pkg/environments/roles.go` - Dynamic role assignment logic
- **Node Registration**: `pkg/bootstrap/registration.go` - Node registration and cluster joining

## Implementation Status: ✅ HASHICORP STACK

**Date:** 2025-10-10  
**Architecture:** HashiCorp Stack (Consul, Nomad, Vault)  
**Cluster Detection:** Consul-based service discovery  
**Storage Orchestration:** Nomad job scheduling  
**Configuration:** Vault secret management  

The Eos bootstrap system uses HashiCorp stack for cluster detection, node registration, and storage operations orchestration. The previous SaltStack-based design has been migrated to HashiCorp architecture.

## Key Features

### Single Node Bootstrap
- Automatic detection of single-node deployment
- Monolithic role assignment
- Local storage configuration
- Standalone Consul/Nomad/Vault setup

### Multi-Node Bootstrap
- Consul-based cluster discovery
- Automatic node registration
- Dynamic role assignment based on cluster size
- Distributed storage configuration

### Storage Operations
- Automatic storage configuration deployment
- Role-based storage thresholds
- Monitoring integration
- Health checks and validation

## Historical Note

The original SaltStack-based design document has been archived at:
`docs/archive/BOOTSTRAP_STORAGE_OPS_DESIGN_SALTSTACK.md`

The current implementation uses HashiCorp stack (Consul, Nomad, Vault) instead of SaltStack for all orchestration and configuration management.

---

> **💡 For comprehensive implementation details, see the inline documentation in the source files listed above.**
