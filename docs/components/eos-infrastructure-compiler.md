# Eos as an Infrastructure Compiler - Architecture Summary

## 1. Vision and Declarative Overview

### What Eos Is
Eos is a thin wrapper around powerful infrastructure tools that acts as a human-friendly infrastructure compiler. It translates imperative human commands into declarative infrastructure state, making orchestration and integration of complex systems simple. It's a conversational interface where users express intent ("I want Nextcloud") and the system handles the complex orchestration required to make that happen.

**Core Philosophy**: Eos doesn't replace existing tools - it makes them work together seamlessly. It's a thin imperative wrapper around a tightly orchestrated environment of declarative systems.

### Core Architecture Flow
```
Human Intent (Imperative) → Eos CLI → SaltStack (Declarative) → Terraform (Resource Provisioning) → Nomad (Container Runtime)
```

### Value Proposition
- **Abstract the Messy Stuff**: Complex multi-system operations become simple commands
- **Encode Once, Use Forever**: Solve problems once, never repeat the research
- **Uniform Interface**: One way to manage everything from storage to containers
- **Institutional Knowledge**: Operational expertise encoded in executable form
- **Point and Click Infrastructure**: As easy as `eos create authentik --frontend-for mailcow`

### Key Principles
- **Human-First Interface**: Users think in actions ("create", "resize", "deploy"), not states
- **Declarative Under the Hood**: All imperative commands compile to declarative configurations
- **Single Source of Truth**: SaltStack serves as the ultimate source of truth for infrastructure state
- **Composable Tools**: Each tool does what it's best at - we compose, not replace
- **Learn Once, Apply Forever**: Solve complex problems once, encode in Eos, never solve again
- **Multi-System Orchestration**: Single commands orchestrate across multiple systems seamlessly
- **Uniform Interface**: One consistent way to manage all infrastructure components

### Multi-System Orchestration Examples

**Wazuh Agent Management**:
```bash
eos update wazuh-agents
```
Behind the scenes:
- Retrieves credentials from password manager
- Formats API call and obtains JWT
- Stores JWT in Vault with expiration tracking
- Updates all agents across fleet
- Logs all actions centrally

**User Creation Workflow**:
```bash
eos create user john.doe
```
Orchestrates:
- Creates user across systems
- Enforces password policy
- Configures auditd rules
- Stores password in Vault
- Sends notification to Teams
- Updates documentation

**Storage Crisis Response**:
```bash
eos expand storage --auto
```
When disk >85% full:
- Analyzes usage patterns
- Determines optimal expansion strategy
- Implements LVM/CephFS changes
- Updates monitoring thresholds

### Example Transformation
**Human says**: `eos create nextcloud --sso --distributed-storage`

**System translates to**:
- SaltStack: Manages physical storage (LVM, CephFS, BTRFS)
- Terraform: Provisions cloud resources (Hetzner reverse proxy)
- Nomad: Deploys containers with proper volume mounts
- Result: Week's worth of work completed in minutes

*Note: Nextcloud is used throughout as an illustrative example of complex multi-system deployments, not as the primary use case.*

## 2. Architectural Decisions and Rationale

### The "Thin Wrapper" Philosophy

**What Eos Is NOT**:
- Not a replacement for existing tools
- Not another orchestration engine
- Not a new configuration language

**What Eos IS**:
- A translation layer between humans and tools
- An integration point for disparate systems
- A repository of encoded operational knowledge
- A consistency enforcer across environments

The power lies in making existing tools work together, not in reimplementing their functionality.

### Why This Stack Order: Eos → SaltStack → Terraform → Nomad

**SaltStack as Foundation**:
- Manages bare metal and physical resources (storage, networking)
- Native support for LVM, filesystems, package management
- Excellent multi-node orchestration capabilities
- Mature, battle-tested storage modules
- Decision: Use Salt for storage because Terraform lacks native LVM/BTRFS/CephFS providers

**Terraform as Cloud Interface**:
- Excels at cloud resource provisioning
- Provides state management for infrastructure
- Has visualization/graphing capabilities
- Acts as bridge between declarative Salt and Nomad
- Decision: Use Terraform for cloud resources, not storage (it's not designed for physical disk management)

**Nomad as Container Runtime**:
- Handles container orchestration
- Simpler than Kubernetes for most use cases
- Integrates well with Consul for service mesh
- Can be managed declaratively through Terraform

### Why Imperative → Declarative Translation

**Human Psychology**:
- People think in actions: "create database", "expand storage"
- Declarative thinking ("ensure state X exists") is unnatural for giving commands
- Commands map to how we communicate about infrastructure
- However, humans find declarative information intuitive to receive and understand
- Eos bridges this gap: imperative input → declarative state → declarative output

**Infrastructure Benefits**:
- Declarative state is auditable and reproducible
- GitOps workflows become possible
- State can be version controlled
- Rollbacks and disaster recovery are simplified
- Configuration drift is automatically detected and corrected

### Storage Architecture Decisions

**Why Not Everything in Terraform**:
- Terraform is designed for cloud APIs, not system administration
- No native providers for LVM, BTRFS, CephFS operations
- Would require custom providers or shell provisioners (fragile)

**Storage Technology Choices**:
- **XFS on LVM**: For databases (best random I/O performance)
- **BTRFS**: For backup targets (compression and deduplication)
- **CephFS**: For distributed storage needs
- **ext4**: For boot/OS (boring is good for boot)

### Example: The Nextcloud Deployment Complexity
*Used as illustration of why this architecture is needed*

Simple request: "Deploy Nextcloud with SSO"

Hidden complexity:
1. Storage: PostgreSQL needs XFS on LVM, files need CephFS, backups need BTRFS
2. Networking: Local server needs Hetzner reverse proxy
3. Identity: Authentik integration for SSO
4. Service Mesh: Consul Connect for secure communication
5. Containers: Proper volume mounts and resource limits

This represents OSI layers 1-7 and typically takes a week of expert work. Eos abstracts away all the "messy stuff" to make this simple - one command instead of days of configuration.

## 3. Remaining Challenges and Imperfections

### State Synchronization
- **Challenge**: Keeping state consistent across Eos, Salt, Terraform, and reality
- **Issue**: Manual changes outside Eos can cause drift
- **Complexity**: Each tool has its own state management approach

### Terraform Storage Limitations
- **Problem**: No native providers for physical storage operations
- **Current Options**: Shell provisioners (fragile) or custom providers (complex)
- **Integration**: Bridging Salt-managed storage with Terraform state

### Cross-Node Coordination
- **Challenge**: Storage operations spanning multiple nodes (CephFS)
- **Timing**: Ensuring operations happen in correct order
- **Rollback**: Atomic operations across distributed systems

### Error Handling and Recovery
- **Issue**: Multi-layer architecture means errors can occur at any level
- **Debugging**: Tracing issues through multiple abstraction layers
- **Recovery**: Partial failures need careful handling

### Performance Considerations
- **Translation Overhead**: Each layer adds latency
- **State Reconciliation**: Can be slow for large infrastructures
- **Storage Operations**: Some operations (BTRFS rebalancing) can impact performance

## 4. Mitigation Strategies and Implementation Plans

### State Management Solutions
```python
# Eos state reconciliation service
class StateReconciler:
    def discover_drift(self):
        salt_state = self.get_salt_state()
        terraform_state = self.get_terraform_state()
        actual_state = self.probe_infrastructure()
        return self.compare_states(salt_state, terraform_state, actual_state)
    
    def reconcile(self):
        # Salt is source of truth
        drift = self.discover_drift()
        self.update_terraform_from_salt()
        self.apply_corrections(drift)
```

### Storage Provider Strategy
**Phase 1**: Use Salt for all storage operations
```yaml
# Salt state for storage
storage:
  lvm:
    pv_present: /dev/sdb
    vg_present: data-vg
    lv_present: 
      name: postgres-data
      size: 100G
```

**Phase 2**: Develop Terraform provider for Salt
```hcl
# Future: terraform-provider-salt
resource "salt_state" "storage" {
  target = "minion-id"
  state = "storage.lvm"
  pillar = {
    size = "100G"
  }
}
```

### Distributed Operation Handling
```yaml
# Salt orchestration for multi-node operations
deploy_cephfs:
  salt.state:
    - tgt: 'ceph:mon'
    - sls: ceph.monitor
    - order: 1
  salt.state:
    - tgt: 'ceph:osd'  
    - sls: ceph.osd
    - order: 2
    - require:
      - salt: deploy_cephfs_mon
```

### Error Recovery Framework
```go
// Eos transaction manager
type Transaction struct {
    Steps []Step
    Checkpoints []Checkpoint
}

func (t *Transaction) Execute() error {
    for i, step := range t.Steps {
        checkpoint := t.saveCheckpoint(i)
        if err := step.Run(); err != nil {
            return t.rollbackTo(checkpoint)
        }
    }
    return nil
}
```

### Monitoring and Observability
- **Metrics**: Instrument each layer with Prometheus metrics
- **Tracing**: OpenTelemetry spans across the stack
- **Visualization**: Leverage Terraform's graph output for visual representation
- **Alerting**: Proactive alerts before storage hits critical thresholds

### Implementation Roadmap
1. **Week 1-2**: Basic Eos CLI with Salt pillar modification
2. **Week 3-4**: Storage management via Salt states
3. **Week 5-6**: Terraform integration for cloud resources
4. **Week 7-8**: Nomad job generation and deployment
5. **Week 9-10**: State reconciliation and error handling
6. **Week 11-12**: Monitoring and visualization layer

### LLM Integration Instructions
When modifying Eos helper functions:
1. All storage operations must go through SaltStack HTTP API
2. Never bypass Salt for direct storage manipulation
3. Maintain declarative state in Salt pillars
4. Use examples (Nextcloud, etc.) as patterns, not requirements
5. Follow the hierarchy: Eos → Salt → Terraform → Nomad

### Key Architectural Invariants
- Salt is always the source of truth
- Eos never executes infrastructure changes directly
- All state changes are auditable and reversible
- Human intent is preserved in declarative form
- Each tool is used for what it's best at
- Complex multi-system operations are abstracted into simple commands
- Operational knowledge is encoded once and reused forever

## Prompt for LLM Guidance

To get comprehensive guidance on implementing storage functionality in Eos:

```
I'm building Eos, a thin wrapper CLI tool that orchestrates infrastructure by translating imperative human commands into declarative configurations managed by SaltStack, Terraform, and Nomad.

Context:
- Eos is NOT replacing existing tools, just making them work together
- Users give imperative commands (eos resize lvm), system maintains declarative state
- SaltStack is the source of truth and handles physical infrastructure
- Terraform manages cloud resources and provides visualization
- Nomad handles container orchestration

Specific Requirements:
1. Show me how to implement storage operations (LVM, XFS, BTRFS, CephFS) through SaltStack
2. Demonstrate how Eos should modify Salt pillars/states to reflect user commands
3. Provide examples of multi-node storage operations (e.g., expanding CephFS across machines)
4. Show integration patterns where one Eos command triggers changes across multiple systems

Key Use Cases:
- eos resize lvm database_volume +50G
- eos create cephfs --nodes node1,node2,node3
- eos convert filesystem /data btrfs --compression zstd

The goal is to abstract away complexity so users don't need to remember pvdisplay commands or CephFS syntax - they just express intent and Eos handles the orchestration.

Please provide:
1. Salt state structures for storage management
2. Python/Go code showing how Eos modifies Salt configurations
3. Examples of error handling and rollback strategies
4. Patterns for encoding operational knowledge (like "expand storage when >80% full")
```