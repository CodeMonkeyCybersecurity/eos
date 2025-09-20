# Bootstrap Storage Operations Integration Design

*Last Updated: 2025-01-19*

## Overview

This document outlines the design for automatically deploying storage operations configurations during the `eos bootstrap` command, with support for both single-node and multi-node deployments.

## Key Design Decisions

### 1. Node Type Detection

During bootstrap, we need to determine if this is:
- **Single Node**: First node in a new infrastructure
- **Additional Node**: Joining an existing EOS infrastructure

Detection methods:
1. **Explicit Flag**: `--join-cluster=<master-ip>` or `--single-node`
2. **Auto-Discovery**: Check for existing  master via multicast/broadcast
3. **Configuration File**: Check for `/etc/eos/cluster.yaml` with cluster info

### 2. Bootstrap Flow

#### Single Node Bootstrap
```
1. Install  (masterless or master mode)
2. Deploy storage ops  states
3. Apply storage configuration for single-node profile
4. Set s: role=monolith, scale=single
5. Start storage monitoring
```

#### Additional Node Bootstrap
```
1. Detect existing cluster
2. Register with  master
3. Trigger orchestration on master
4. Master reassigns roles cluster-wide
5. Deploy appropriate storage configs
6. Update monitoring topology
```

## Implementation Microsteps

### Phase 1: Detection and Decision

```go
// pkg/bootstrap/detector.go
type ClusterInfo struct {

    NodeCount    int
    MyRole       environment.Role
    ClusterID    string
}

func DetectClusterState(rc *eos_io.RuntimeContext) (*ClusterInfo, error) {
    // 1. Check explicit flags
    // 2. Try  master discovery
    // 3. Check local config file
    // 4. Default to single-node
}
```

### Phase 2: Node Registration

```go
// pkg/bootstrap/registration.go
type NodeRegistration struct {
    Hostname    string
    IP          string
    Resources   ResourceInfo
    RequestRole string // Preferred role
}

func RegisterNode(rc *eos_io.RuntimeContext, master string, reg NodeRegistration) error {
    // 1. Connect to  master
    // 2. Submit registration
    // 3. Wait for acceptance
    // 4. Receive initial configuration
}
```

### Phase 3:  Orchestration

```yaml
# /orchestration/node_addition.sls
{% set new_node = ..get('new_node') %}
{% set current_nodes = ['mine.get']('*', 'node_info') %}

# Step 1: Accept new node
accept_new_node:
  .wheel:
    - name: key.accept
    - match: {{ new_node.hostname }}

# Step 2: Calculate new roles
{% set new_roles = ['eos_roles.recalculate'](current_nodes, new_node) %}

# Step 3: Update all node roles
{% for node, role in new_roles.items() %}
update_{{ node }}_role:
  .state:
    - tgt: {{ node }}
    - sls:
      - roles.{{ role }}
      - storage.config
    - :
      role: {{ role }}
      scale: {{ new_roles.scale }}
{% endfor %}

# Step 4: Update storage thresholds
update_storage_thresholds:
  .state:
    - tgt: '*'
    - sls: storage.thresholds
    - :
      scale: {{ new_roles.scale }}
```

### Phase 4: Role Reassignment Logic

```go
// pkg/bootstrap/roles.go
func RecalculateRoles(existingNodes []Machine, newNode Machine) map[string]Role {
    totalNodes := len(existingNodes) + 1
    
    switch totalNodes {
    case 2:
        // First node becomes edge, second becomes core
        return assignTwoNodeRoles(existingNodes, newNode)
    case 3:
        // edge, core, data
        return assignThreeNodeRoles(existingNodes, newNode)
    default:
        // More complex assignment based on resources
        return assignDistributedRoles(existingNodes, newNode)
    }
}
```

### Phase 5: Storage Configuration Distribution

```yaml
# /storage/config.sls
{% set scale = s.get('scale', 'single') %}
{% set role = s.get('role', 'monolith') %}

/etc/eos/storage-ops.yaml:
  file.managed:
    - source: ://storage/files/storage-ops.yaml.jinja
    - template: jinja
    - context:
        scale: {{ scale }}
        role: {{ role }}
        thresholds: {{ .get('storage_thresholds') }}

storage_monitor_service:
  file.managed:
    - name: /etc/systemd/system/eos-storage-monitor.service
    - source: ://storage/files/storage-monitor.service
  service.running:
    - name: eos-storage-monitor
    - enable: True
    - watch:
      - file: /etc/eos/storage-ops.yaml
```

## Bootstrap Command Updates

```go
// cmd/create/bootstrap.go additions

var (
    joinCluster   string
    singleNode    bool
    preferredRole string
)

func init() {
    bootstrapCmd.Flags().StringVar(&joinCluster, "join-cluster", "", 
        "Join existing cluster at specified master address")
    bootstrapCmd.Flags().BoolVar(&singleNode, "single-node", false,
        "Explicitly configure as single-node deployment")
    bootstrapCmd.Flags().StringVar(&preferredRole, "preferred-role", "",
        "Preferred role when joining cluster (edge/core/data/compute)")
}

func runBootstrapAll(rc *eos_io.RuntimeContext, cmd *cobra.Command, args []string) error {
    logger := otelzap.Ctx(rc.Ctx)
    
    // Detect cluster state
    clusterInfo, err := bootstrap.DetectClusterState(rc, bootstrap.Options{
        JoinCluster:   joinCluster,
        SingleNode:    singleNode,
        PreferredRole: preferredRole,
    })
    if err != nil {
        return fmt.Errorf("failed to detect cluster state: %w", err)
    }
    
    if clusterInfo.IsMaster || singleNode {
        // Single node or first master
        logger.Info("Bootstrapping as single node or first master")
        return bootstrapSingleNode(rc, clusterInfo)
    } else {
        // Joining existing cluster
        logger.Info("Bootstrapping as additional node",
            zap.String("master", clusterInfo.))
        return bootstrapAdditionalNode(rc, clusterInfo)
    }
}
```

## Communication Flow

### Node Addition Sequence
```
New Node                    Master                      Existing Nodes
   |                          |                              |
   |------ Register --------->|                              |
   |                          |                              |
   |<----- Accept Key --------|                              |
   |                          |                              |
   |                          |------- Mine Update --------->|
   |                          |                              |
   |                          |<------ Node Info -----------|
   |                          |                              |
   |                          |-- Calculate New Roles -------|
   |                          |                              |
   |<---- Deploy Config ------|                              |
   |                          |                              |
   |                          |------ Update Roles --------->|
   |                          |                              |
   |<---------- Storage Config Sync ------------------------>|
```

##  States Structure

```
/
├── storage/
│   ├── init.sls              # Main storage state
│   ├── config.sls             # Configuration deployment
│   ├── monitor.sls            # Monitoring setup
│   ├── thresholds.sls         # Threshold configuration
│   └── files/
│       ├── storage-ops.yaml.jinja
│       └── storage-monitor.service
├── orchestration/
│   ├── node_addition.sls      # Node addition orchestration
│   └── role_update.sls        # Role update orchestration
└── roles/
    ├── monolith.sls           # Single node role
    ├── edge.sls               # Edge server role
    ├── core.sls               # Core services role
    ├── data.sls               # Data storage role
    └── compute.sls            # Compute node role
```

## Safety and Rollback

### Pre-checks
1. Verify  connectivity
2. Check disk space on all nodes
3. Validate network connectivity
4. Ensure no ongoing operations

### Rollback Mechanism
```go
type BootstrapCheckpoint struct {
    Timestamp   time.Time
    Stage       string
    NodeStates  map[string]NodeState
    CanRollback bool
}

func CreateCheckpoint(rc *eos_io.RuntimeContext, stage string) (*BootstrapCheckpoint, error)
func RollbackToCheckpoint(rc *eos_io.RuntimeContext, checkpoint *BootstrapCheckpoint) error
```

## Configuration Examples

### Single Node Bootstrap
```bash
# Explicit single node
eos bootstrap --single-node

# Auto-detected single node (no cluster found)
eos bootstrap
```

### Joining Existing Cluster
```bash
# Join with explicit master
eos bootstrap --join-cluster=10.0.1.10

# Join with role preference
eos bootstrap --join-cluster=10.0.1.10 --preferred-role=data

# Auto-discovery (multicast)
eos bootstrap --auto-discover
```

### Cluster Configuration File
```yaml
# /etc/eos/cluster.yaml
cluster:
  id: prod-cluster-001
  master: 10.0.1.10
  discovery:
    method: multicast
    port: 4505
  roles:
    assignment: automatic
    rebalance_on_join: true
```

## Testing Strategy

1. **Single Node**: Verify standalone deployment
2. **Two Nodes**: Test edge/core assignment
3. **Three Nodes**: Test edge/core/data assignment
4. **Scale Up**: Add 4th, 5th nodes and verify role distribution
5. **Failure Cases**: Network partition,  master failure
6. **Rollback**: Test checkpoint and recovery

## Summary

This design provides:
1. **Automatic Detection**: Smart detection of deployment type
2. **Seamless Scaling**: Easy addition of nodes to existing clusters
3. **Dynamic Roles**: Automatic role assignment based on cluster size
4. **Safe Operations**: Pre-checks and rollback capabilities
5. **Simple Interface**: Minimal configuration required

The implementation focuses on simplicity while maintaining flexibility for complex deployments.