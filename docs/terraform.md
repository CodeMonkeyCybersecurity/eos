# Terraform bits

## Complete EOS Infrastructure Compiler Implementation
```
eos-infrastructure/
├── salt/
│   ├── orchestrate/
│   │   ├── init.sls
│   │   ├── deploy.sls
│   │   └── destroy.sls
│   ├── terraform/
│   │   ├── init.sls
│   │   ├── backends.sls
│   │   └── providers.sls
│   ├── _modules/
│   │   ├── eos_terraform.py
│   │   └── eos_orchestrator.py
│   ├── _runners/
│   │   └── infrastructure.py
│   ├── _states/
│   │   └── terraform_resource.py
│   └── components/
│       ├── vault/
│       ├── consul/
│       ├── boundary/
│       ├── hecate/
│       └── hera/
├── terraform/
│   ├── modules/
│   │   ├── vault-cluster/
│   │   ├── consul-cluster/
│   │   ├── boundary-cluster/
│   │   ├── hecate-proxy/
│   │   └── hera-framework/
│   └── environments/
│       ├── production/
│       └── staging/
└── pillar/
    ├── infrastructure/
    │   ├── common.sls
    │   ├── production.sls
    │   └── staging.sls
    └── credentials/
        └── vault.sls
```

## How should saltstack  automate and orchestrate terraform for cloud based resources (eg hashicorp boundary instances, hecate reverse proxy framework, azure llm instances, offsite backups, hetzner vms and other resources) in the eos infrastructure compiler, what would be the most architecturally sensible way to do this? what issues will we encounter?

Let me think through the architectural considerations for integrating SaltStack with Terraform in your EOS infrastructure compiler context.

## Architectural Approaches

### 1. **Salt as the Orchestration Layer**

The most sensible approach would be to position SaltStack as the high-level orchestrator that manages Terraform executions. Here's my reasoning:

**Salt States Managing Terraform Runs**
```yaml
# Example: salt/states/terraform/boundary.sls
boundary_terraform_workspace:
  file.directory:
    - name: /srv/terraform/boundary
    - makedirs: True

boundary_terraform_files:
  file.managed:
    - name: /srv/terraform/boundary/main.tf
    - source: salt://terraform/boundary/main.tf
    - template: jinja
    - defaults:
        region: {{ pillar['boundary']['region'] }}
        instance_count: {{ pillar['boundary']['instance_count'] }}

boundary_terraform_init:
  cmd.run:
    - name: terraform init
    - cwd: /srv/terraform/boundary
    - require:
      - file: boundary_terraform_files

boundary_terraform_apply:
  cmd.run:
    - name: terraform apply -auto-approve
    - cwd: /srv/terraform/boundary
    - require:
      - cmd: boundary_terraform_init
```

### 2. **State Storage Architecture**

I'd recommend a hybrid state management approach:

```
┌─────────────────┐
│   Salt Master   │
│  (Orchestrator) │
└────────┬────────┘
         │
    ┌────┴────┐
    │         │
┌───▼───┐ ┌──▼────────┐
│ Local │ │  Remote   │
│ State │ │ TF State  │
│ Cache │ │ (S3/Azure)│
└───────┘ └───────────┘
```

**Reasoning**: This allows Salt to track deployment status while Terraform maintains its own state remotely for collaboration and locking.

### 3. **Execution Models**

**Option A: Direct Execution** (Simpler but less scalable)
```python
# Custom Salt execution module
def apply_terraform(workspace, variables=None):
    """
    Execute terraform apply with Salt-provided variables
    """
    tf_dir = f"/srv/terraform/{workspace}"
    
    # Write variables from Salt pillar
    if variables:
        with open(f"{tf_dir}/terraform.tfvars", 'w') as f:
            for key, value in variables.items():
                f.write(f'{key} = "{value}"\n')
    
    # Run terraform
    ret = __salt__['cmd.run_all'](
        f'terraform apply -auto-approve',
        cwd=tf_dir
    )
    return ret
```

**Option B: Runner-Based** (Better for complex orchestrations)
```python
# Salt runner for terraform orchestration
def orchestrate_infrastructure(env='production'):
    """
    Orchestrate entire infrastructure deployment
    """
    # Order matters for dependencies
    deployments = [
        ('networking', {'vpc_cidr': '10.0.0.0/16'}),
        ('boundary', {'depends_on': 'networking'}),
        ('hecate_proxy', {'upstream_boundary': True}),
        ('azure_llm', {'instance_type': 'NC24ads_A100_v4'}),
    ]
    
    for component, config in deployments:
        __salt__['state.apply'](
            f'terraform.{component}',
            pillar=config
        )
```

## Integration Architecture Pattern

Here's what I consider the most architecturally sensible approach:

```yaml
# Master configuration
ext_pillar:
  - terraform_outputs:
      backend: s3
      bucket: eos-terraform-state
      
# This allows Salt to read Terraform outputs as pillar data
```

```python
# Custom Salt module for Terraform integration
import json
import subprocess

def get_terraform_output(workspace, output_name):
    """
    Retrieve Terraform output values for use in Salt states
    """
    cmd = f"terraform output -json {output_name}"
    result = subprocess.run(
        cmd.split(), 
        cwd=f"/srv/terraform/{workspace}",
        capture_output=True
    )
    return json.loads(result.stdout)

def ensure_infrastructure(component, desired_state):
    """
    Idempotent infrastructure ensure function
    """
    current = get_terraform_output(component, 'state_hash')
    if current != desired_state['hash']:
        return apply_terraform(component, desired_state)
    return {'result': True, 'changes': False}
```

## Issues You'll Encounter

### 1. **State Synchronization Challenges**

**Problem**: Salt and Terraform maintain separate state mechanisms.

**Solution**: 
```yaml
# Implement state bridge
terraform_state_sync:
  schedule.present:
    - function: terraform.sync_states
    - seconds: 300
    - maxrunning: 1
```

### 2. **Credential Management Complexity**

**Problem**: Multiple cloud providers require different auth mechanisms.

```python
# Credential injection pattern
def inject_credentials(provider, workspace):
    """
    Inject provider-specific credentials
    """
    creds = {
        'azure': {
            'ARM_CLIENT_ID': __salt__['pillar.get']('azure:client_id'),
            'ARM_CLIENT_SECRET': __salt__['vault.read_secret']('azure/client_secret'),
        },
        'hetzner': {
            'HCLOUD_TOKEN': __salt__['vault.read_secret']('hetzner/api_token'),
        }
    }
    
    return creds.get(provider, {})
```

### 3. **Dependency Resolution**

**Problem**: Complex dependencies between resources across providers.

**Solution**: Implement a dependency graph resolver:

```python
class InfrastructureDependencyResolver:
    def __init__(self):
        self.graph = {
            'boundary': ['networking', 'dns'],
            'hecate_proxy': ['boundary', 'load_balancer'],
            'azure_llm': ['networking', 'storage'],
            'backups': ['*'],  # Depends on everything
        }
    
    def get_deployment_order(self):
        # Topological sort implementation
        pass
```

### 4. **Rollback Complexity**

**Problem**: Terraform destroy isn't always clean, especially with stateful services.

```yaml
# Implement staged rollback
rollback_infrastructure:
  salt.runner:
    - name: terraform.staged_rollback
    - components:
        - backups  # Safe to remove first
        - azure_llm
        - hecate_proxy
        - boundary  # Has data, remove carefully
    - preserve_data: True
```

### 5. **Resource Drift Detection**

```python
def detect_drift(component):
    """
    Detect when real infrastructure differs from Terraform state
    """
    plan_output = __salt__['cmd.run'](
        f'terraform plan -detailed-exitcode',
        cwd=f'/srv/terraform/{component}'
    )
    
    # Exit code 2 means drift detected
    if plan_output['retcode'] == 2:
        return {
            'drift_detected': True,
            'changes': parse_plan_output(plan_output['stdout'])
        }
```

### 6. **Concurrent Execution Issues**

**Problem**: Multiple Salt minions trying to run Terraform simultaneously.

**Solution**: Implement distributed locking:

```python
def acquire_terraform_lock(workspace):
    """
    Use Salt's presence system for distributed locking
    """
    lock_key = f"terraform_lock_{workspace}"
    if __salt__['presence.present'](lock_key, __grains__['id']):
        return True
    return False
```

## Specific Resource Considerations

### For HashiCorp Boundary
- Need to handle unseal keys securely
- Post-deployment configuration via Salt

### For Hecate Proxy
- Dynamic upstream configuration based on Terraform outputs
- Health check integration

### For Azure LLM Instances
- GPU availability checking before deployment
- Cost monitoring integration

### For Hetzner VMs
- API rate limiting handling
- Floating IP reassignment during updates

## Recommended Architecture

```
┌─────────────────────────────────────────┐
│         EOS Compiler Frontend           │
└────────────────┬───────────────────────┘
                 │
┌────────────────▼───────────────────────┐
│         Salt Master/API                 │
│  - Orchestration Logic                  │
│  - State Management                     │
│  - Credential Injection                 │
└────────────────┬───────────────────────┘
                 │
┌────────────────▼───────────────────────┐
│      Terraform Execution Layer          │
│  - Workspace per Component              │
│  - Remote State (S3/Azure)              │
│  - Provider Plugins                     │
└────────────────┬───────────────────────┘
                 │
        ┌────────┴────────┐
        │                 │
┌───────▼──────┐ ┌────────▼────────┐
│ Cloud APIs   │ │ On-Prem APIs    │
│ (Azure, etc) │ │ (Hetzner, etc)  │
└──────────────┘ └─────────────────┘
```

This architecture provides clear separation of concerns while maintaining the flexibility you need for complex multi-cloud orchestration.