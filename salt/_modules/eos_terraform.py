#!/usr/bin/env python3
"""
EOS Terraform Integration Module
Handles all Terraform operations with proper state management
"""
import json
import os
import time
import hashlib
import subprocess
from pathlib import Path
import tempfile
import logging

# Try to import Salt utilities
try:
    import salt.utils.vault
    import salt.utils.consul
    HAS_SALT_UTILS = True
except ImportError:
    HAS_SALT_UTILS = False

log = logging.getLogger(__name__)

__virtualname__ = 'eos_terraform'

def __virtual__():
    """Only load if terraform binary is available"""
    return __virtualname__ if salt.utils.path.which('terraform') else False

class TerraformWorkspace:
    """Manages individual Terraform workspaces"""
    
    def __init__(self, component, environment='production'):
        self.component = component
        self.environment = environment
        self.workspace_path = Path(f'/srv/terraform/{environment}/{component}')
        self.state_lock_key = f'terraform/{environment}/{component}/lock'
        
    def acquire_lock(self, ttl=600):
        """Acquire distributed lock via Consul"""
        if not HAS_SALT_UTILS:
            log.warning("Salt utils not available, skipping lock acquisition")
            return None
            
        consul_client = salt.utils.consul.get_conn()
        session = consul_client.session.create(ttl=ttl)
        acquired = consul_client.kv.put(
            self.state_lock_key,
            __grains__['id'],
            acquire=session
        )
        return session if acquired else None
    
    def release_lock(self, session):
        """Release Consul lock"""
        if not session or not HAS_SALT_UTILS:
            return
            
        consul_client = salt.utils.consul.get_conn()
        consul_client.session.destroy(session)

def init_workspace(component, environment='production', backend_config=None):
    """
    Initialize Terraform workspace with remote state backend
    
    CLI Example:
        salt '*' eos_terraform.init_workspace vault production
    """
    workspace = TerraformWorkspace(component, environment)
    
    # Ensure workspace directory exists
    workspace.workspace_path.mkdir(parents=True, exist_ok=True)
    
    # Generate backend configuration
    if backend_config:
        backend_tf = _generate_backend_config(component, environment, backend_config)
        (workspace.workspace_path / 'backend.tf').write_text(backend_tf)
    
    # Initialize Terraform
    lock = workspace.acquire_lock()
    if not lock:
        return {'result': False, 'error': 'Failed to acquire lock'}
    
    try:
        cmd = ['terraform', 'init', '-reconfigure']
        result = _run_terraform_command(cmd, workspace.workspace_path)
        
        if result['retcode'] == 0:
            # Store initialization state in Consul
            _store_workspace_metadata(component, environment, 'initialized')
            return {'result': True, 'output': result['stdout']}
        else:
            return {'result': False, 'error': result['stderr']}
    finally:
        workspace.release_lock(lock)

def plan(component, environment='production', variables=None, destroy=False):
    """
    Generate Terraform execution plan
    
    CLI Example:
        salt '*' eos_terraform.plan hecate production '{"instance_count": 3}'
    """
    workspace = TerraformWorkspace(component, environment)
    
    # Check if workspace is initialized
    if not (workspace.workspace_path / '.terraform').exists():
        return {'result': False, 'error': 'Workspace not initialized - run init first'}
    
    # Generate tfvars file
    if variables:
        tfvars = _generate_tfvars(component, environment, variables)
        tfvars_path = workspace.workspace_path / 'terraform.tfvars.json'
        tfvars_path.write_text(json.dumps(tfvars, indent=2))
    
    # Acquire lock
    lock = workspace.acquire_lock()
    if not lock:
        return {'result': False, 'error': 'Failed to acquire lock'}
    
    try:
        cmd = ['terraform', 'plan', '-detailed-exitcode', '-out=tfplan']
        if destroy:
            cmd.append('-destroy')
        
        # Set provider credentials
        env = _get_provider_credentials(component)
        
        result = _run_terraform_command(cmd, workspace.workspace_path, env=env)
        
        # Exit codes: 0=no changes, 1=error, 2=changes present
        if result['retcode'] in [0, 2]:
            changes_present = result['retcode'] == 2
            
            # Parse plan for detailed changes
            plan_cmd = ['terraform', 'show', '-json', 'tfplan']
            plan_json_result = _run_terraform_command(plan_cmd, workspace.workspace_path)
            
            if plan_json_result['retcode'] == 0:
                plan_data = json.loads(plan_json_result['stdout'])
                resource_changes = _parse_plan_changes(plan_data)
            else:
                resource_changes = []
            
            return {
                'result': True,
                'changes_present': changes_present,
                'resource_changes': resource_changes,
                'plan_file': 'tfplan'
            }
        else:
            return {'result': False, 'error': result['stderr']}
    finally:
        workspace.release_lock(lock)

def apply(component, environment='production', plan_file=None, auto_approve=False):
    """
    Apply Terraform changes
    
    CLI Example:
        salt '*' eos_terraform.apply hecate production plan_file=tfplan
        salt '*' eos_terraform.apply hecate production auto_approve=True
    """
    workspace = TerraformWorkspace(component, environment)
    
    # Verify pre-conditions
    if not _verify_preconditions(component, environment):
        return {'result': False, 'error': 'Preconditions not met'}
    
    lock = workspace.acquire_lock(ttl=1800)  # 30 min for long operations
    if not lock:
        return {'result': False, 'error': 'Failed to acquire lock'}
    
    try:
        # Take pre-apply snapshot
        snapshot_id = _create_state_snapshot(component, environment)
        
        cmd = ['terraform', 'apply']
        if plan_file:
            cmd.append(plan_file)
        elif auto_approve:
            cmd.append('-auto-approve')
        else:
            return {'result': False, 'error': 'Must provide plan_file or auto_approve'}
        
        # Set provider credentials
        env = _get_provider_credentials(component)
        
        result = _run_terraform_command(cmd, workspace.workspace_path, env=env, timeout=1800)
        
        if result['retcode'] == 0:
            # Extract outputs
            outputs = get_outputs(component, environment)
            
            # Store outputs in Consul for other services
            _store_outputs_in_consul(component, environment, outputs)
            
            # Update component metadata
            _update_component_metadata(component, environment, 'applied', snapshot_id)
            
            # Trigger post-apply hooks
            _run_post_apply_hooks(component, environment, outputs)
            
            return {
                'result': True,
                'outputs': outputs,
                'snapshot_id': snapshot_id
            }
        else:
            # Automatic rollback on failure
            if snapshot_id and auto_approve:
                rollback_result = rollback_to_snapshot(component, environment, snapshot_id)
                return {
                    'result': False,
                    'error': result['stderr'],
                    'rollback_attempted': True,
                    'rollback_result': rollback_result
                }
            return {'result': False, 'error': result['stderr']}
    finally:
        workspace.release_lock(lock)

def get_outputs(component, environment='production'):
    """
    Get Terraform outputs
    
    CLI Example:
        salt '*' eos_terraform.get_outputs hecate production
    """
    workspace = TerraformWorkspace(component, environment)
    
    cmd = ['terraform', 'output', '-json']
    result = _run_terraform_command(cmd, workspace.workspace_path)
    
    if result['retcode'] == 0:
        outputs = json.loads(result['stdout'])
        # Extract just the values
        return {k: v.get('value') for k, v in outputs.items()}
    else:
        return {}

def deploy_nomad_service(service_name, environment='production', service_config=None, auto_approve=False):
    """
    Deploy a containerized service using Terraform → Nomad pattern
    
    Args:
        service_name: Name of the service to deploy (e.g., 'jenkins', 'grafana')
        environment: Environment/workspace (production, staging, dev)
        service_config: Service-specific configuration dictionary
        auto_approve: Skip confirmation prompts
    
    CLI Example:
        salt '*' eos_terraform.deploy_nomad_service jenkins production \
            service_config='{"admin_password": "secret", "port": 8080}' \
            auto_approve=True
    """
    if service_config is None:
        service_config = {}
    
    # Service is treated as a Terraform component
    workspace = TerraformWorkspace(f"nomad-{service_name}", environment)
    
    # Generate Terraform configuration for Nomad job
    terraform_config = _generate_nomad_service_terraform(service_name, service_config)
    
    # Write Terraform configuration
    config_path = workspace.workspace_path / 'main.tf'
    workspace.workspace_path.mkdir(parents=True, exist_ok=True)
    
    with open(config_path, 'w') as f:
        f.write(terraform_config)
    
    # Apply Terraform configuration (which deploys Nomad job)
    return apply(f"nomad-{service_name}", environment, auto_approve=auto_approve)

def _generate_nomad_service_terraform(service_name, config):
    """
    Generate Terraform configuration that creates a Nomad job
    
    This creates a Terraform configuration that uses the nomad provider
    to deploy containerized services as Nomad jobs.
    """
    # Service-specific template generation
    if service_name == 'jenkins':
        return _generate_jenkins_terraform(config)
    elif service_name == 'grafana':
        return _generate_grafana_terraform(config)
    elif service_name == 'umami':
        return _generate_umami_terraform(config)
    else:
        # Generic service template
        return _generate_generic_service_terraform(service_name, config)

def _generate_jenkins_terraform(config):
    """Generate Terraform configuration for Jenkins deployment via Nomad"""
    admin_password = config.get('admin_password', 'admin')
    port = config.get('port', 8080)
    datacenter = config.get('datacenter', 'dc1')
    
    return f'''
terraform {{
  required_providers {{
    nomad = {{
      source  = "hashicorp/nomad"
      version = "~> 2.0"
    }}
    consul = {{
      source  = "hashicorp/consul"
      version = "~> 2.0"
    }}
  }}
}}

provider "nomad" {{
  address = "http://localhost:4646"
}}

provider "consul" {{
  address = "localhost:8500"
}}

resource "nomad_job" "jenkins" {{
  jobspec = templatefile("${{path.module}}/jenkins.nomad.tpl", {{
    admin_password = "{admin_password}"
    port          = {port}
    datacenter    = "{datacenter}"
    data_path     = "/opt/jenkins/data"
  }})
  
  purge_on_destroy = true
  detach          = false
}}

# Create Nomad job template file
resource "local_file" "jenkins_job_template" {{
  filename = "${{path.module}}/jenkins.nomad.tpl"
  content  = <<-EOT
job "jenkins" {{
  datacenters = ["{datacenter}"]
  type        = "service"
  
  group "jenkins" {{
    count = 1
    
    network {{
      port "http" {{ 
        to = {port}
      }}
      port "agent" {{
        to = 50000
      }}
    }}
    
    volume "jenkins_data" {{
      type   = "host"
      source = "jenkins_data"
    }}
    
    task "jenkins" {{
      driver = "docker"
      
      config {{
        image = "jenkins/jenkins:lts"
        ports = ["http", "agent"]
      }}
      
      volume_mount {{
        volume      = "jenkins_data"
        destination = "/var/jenkins_home"
      }}
      
      service {{
        name = "jenkins"
        port = "http"
        
        tags = [
          "ci-cd",
          "automation",
          "eos-managed"
        ]
        
        check {{
          type     = "http"
          path     = "/login"
          interval = "10s"
          timeout  = "3s"
        }}
      }}
      
      resources {{
        cpu    = 500
        memory = 1024
      }}
      
      env {{
        JAVA_OPTS = "-Djenkins.install.runSetupWizard=false"
        JENKINS_ADMIN_PASSWORD = "{admin_password}"
      }}
    }}
  }}
}}
EOT
}}

output "jenkins_url" {{
  value = "http://localhost:{port}"
}}

output "jenkins_consul_service" {{
  value = "jenkins.service.consul"
}}

output "jenkins_admin_password" {{
  value     = "{admin_password}"
  sensitive = true
}}
'''

def destroy(component, environment='production', auto_approve=False):
    """
    Destroy Terraform-managed infrastructure
    
    CLI Example:
        salt '*' eos_terraform.destroy hecate production auto_approve=True
    """
    workspace = TerraformWorkspace(component, environment)
    
    # Generate destroy plan first
    plan_result = plan(component, environment, destroy=True)
    if not plan_result['result']:
        return plan_result
    
    if not plan_result['changes_present']:
        return {'result': True, 'message': 'No resources to destroy'}
    
    # Apply destroy plan
    apply_result = apply(component, environment, plan_file='tfplan', auto_approve=auto_approve)
    
    if apply_result['result']:
        # Clean up Consul entries
        _cleanup_consul_entries(component, environment)
        
    return apply_result

def get_resources(component, environment='production'):
    """
    Get list of Terraform-managed resources
    
    CLI Example:
        salt '*' eos_terraform.get_resources hecate production
    """
    workspace = TerraformWorkspace(component, environment)
    
    cmd = ['terraform', 'state', 'list']
    result = _run_terraform_command(cmd, workspace.workspace_path)
    
    if result['retcode'] == 0:
        resources = result['stdout'].strip().split('\n')
        return {'result': True, 'resources': resources}
    else:
        return {'result': False, 'error': result['stderr']}

def get_state(component, environment='production', resource=None):
    """
    Get Terraform state information
    
    CLI Example:
        salt '*' eos_terraform.get_state hecate production
        salt '*' eos_terraform.get_state hecate production resource=aws_instance.web
    """
    workspace = TerraformWorkspace(component, environment)
    
    cmd = ['terraform', 'state', 'show']
    if resource:
        cmd.append(resource)
    
    result = _run_terraform_command(cmd, workspace.workspace_path)
    
    if result['retcode'] == 0:
        return {'result': True, 'state': result['stdout']}
    else:
        return {'result': False, 'error': result['stderr']}

def import_resource(component, environment, resource_address, resource_id):
    """
    Import existing resource into Terraform state
    
    CLI Example:
        salt '*' eos_terraform.import_resource hecate production aws_instance.web i-1234567890abcdef0
    """
    workspace = TerraformWorkspace(component, environment)
    
    lock = workspace.acquire_lock()
    if not lock:
        return {'result': False, 'error': 'Failed to acquire lock'}
    
    try:
        cmd = ['terraform', 'import', resource_address, resource_id]
        env = _get_provider_credentials(component)
        
        result = _run_terraform_command(cmd, workspace.workspace_path, env=env)
        
        if result['retcode'] == 0:
            return {'result': True, 'message': f'Successfully imported {resource_address}'}
        else:
            return {'result': False, 'error': result['stderr']}
    finally:
        workspace.release_lock(lock)

def rollback_to_snapshot(component, environment, snapshot_id):
    """
    Rollback to a previous state snapshot
    
    CLI Example:
        salt '*' eos_terraform.rollback_to_snapshot hecate production abc123
    """
    workspace = TerraformWorkspace(component, environment)
    snapshot_path = workspace.workspace_path / f'.snapshots/{snapshot_id}.tfstate'
    state_file = workspace.workspace_path / 'terraform.tfstate'
    
    if not snapshot_path.exists():
        return {'result': False, 'error': 'Snapshot not found'}
    
    lock = workspace.acquire_lock()
    if not lock:
        return {'result': False, 'error': 'Failed to acquire lock'}
    
    try:
        # Copy snapshot back to state file
        import shutil
        shutil.copy2(snapshot_path, state_file)
        
        # Run terraform refresh to sync with actual resources
        cmd = ['terraform', 'refresh']
        env = _get_provider_credentials(component)
        
        result = _run_terraform_command(cmd, workspace.workspace_path, env=env)
        
        if result['retcode'] == 0:
            return {'result': True, 'message': 'Successfully rolled back to snapshot'}
        else:
            return {'result': False, 'error': f'Rollback failed: {result["stderr"]}'}
    finally:
        workspace.release_lock(lock)

def component_is_healthy(component, environment='production'):
    """
    Check if a component is deployed and healthy
    
    CLI Example:
        salt '*' eos_terraform.component_is_healthy vault production
    """
    if not HAS_SALT_UTILS:
        return False
        
    # Check Consul for health status
    consul_client = salt.utils.consul.get_conn()
    health_key = f'terraform/{environment}/{component}/health'
    
    try:
        _, data = consul_client.kv.get(health_key)
        if data and data['Value']:
            return data['Value'].decode('utf-8') == 'healthy'
    except Exception as e:
        log.error(f"Failed to check component health: {e}")
    
    return False

# Helper functions

def _run_terraform_command(cmd, cwd, env=None, timeout=300):
    """Run a terraform command and return the result"""
    try:
        # Merge environment variables
        cmd_env = os.environ.copy()
        if env:
            cmd_env.update(env)
        
        result = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=cmd_env
        )
        
        return {
            'retcode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr
        }
    except subprocess.TimeoutExpired:
        return {
            'retcode': -1,
            'stdout': '',
            'stderr': f'Command timed out after {timeout} seconds'
        }
    except Exception as e:
        return {
            'retcode': -1,
            'stdout': '',
            'stderr': str(e)
        }

def _generate_backend_config(component, environment, backend_config):
    """Generate backend configuration for state management"""
    if not HAS_SALT_UTILS:
        return ""
        
    vault_client = salt.utils.vault.get_vault_connection()
    backend_creds = vault_client.read(f'secret/terraform/{environment}/backend')
    
    if not backend_creds or 'data' not in backend_creds:
        log.error("Failed to retrieve backend credentials from Vault")
        return ""
    
    data = backend_creds['data']
    
    return f"""
terraform {{
  backend "s3" {{
    bucket         = "{data.get('bucket', '')}"
    key            = "{environment}/{component}/terraform.tfstate"
    region         = "{data.get('region', '')}"
    dynamodb_table = "{data.get('dynamodb_table', '')}"
    encrypt        = true
    
    access_key = "{data.get('access_key', '')}"
    secret_key = "{data.get('secret_key', '')}"
  }}
}}
"""

def _get_provider_credentials(component):
    """Retrieve provider-specific credentials from Vault"""
    if not HAS_SALT_UTILS:
        return {}
        
    vault_client = salt.utils.vault.get_vault_connection()
    
    # Map components to their required providers
    provider_map = {
        'boundary': ['aws', 'tls'],
        'consul': ['aws', 'consul'],
        'vault': ['aws', 'vault'],
        'hecate': ['aws', 'cloudflare'],
        'hera': ['azure', 'kubernetes'],
        'backups': ['hetzner', 'b2'],
    }
    
    env_vars = {}
    
    for provider in provider_map.get(component, []):
        try:
            creds = vault_client.read(f'secret/providers/{provider}')
            if creds and 'data' in creds:
                # Map credentials to environment variables
                if provider == 'aws':
                    env_vars.update({
                        'AWS_ACCESS_KEY_ID': creds['data'].get('access_key', ''),
                        'AWS_SECRET_ACCESS_KEY': creds['data'].get('secret_key', ''),
                        'AWS_REGION': creds['data'].get('region', '')
                    })
                elif provider == 'azure':
                    env_vars.update({
                        'ARM_CLIENT_ID': creds['data'].get('client_id', ''),
                        'ARM_CLIENT_SECRET': creds['data'].get('client_secret', ''),
                        'ARM_SUBSCRIPTION_ID': creds['data'].get('subscription_id', ''),
                        'ARM_TENANT_ID': creds['data'].get('tenant_id', '')
                    })
                elif provider == 'hetzner':
                    env_vars['HCLOUD_TOKEN'] = creds['data'].get('api_token', '')
                elif provider == 'cloudflare':
                    env_vars.update({
                        'CLOUDFLARE_API_TOKEN': creds['data'].get('api_token', ''),
                        'CLOUDFLARE_ZONE_ID': creds['data'].get('zone_id', '')
                    })
        except Exception as e:
            log.error(f"Failed to get {provider} credentials: {e}")
    
    return env_vars

def _generate_tfvars(component, environment, additional_vars=None):
    """Generate Terraform variables from Salt pillar data"""
    base_vars = __salt__['pillar.get'](f'infrastructure:{component}', {})
    env_vars = __salt__['pillar.get'](f'infrastructure:{environment}:{component}', {})
    
    # Merge variables with precedence
    tfvars = {}
    tfvars.update(base_vars)
    tfvars.update(env_vars)
    if additional_vars:
        tfvars.update(additional_vars)
    
    # Add standard variables
    tfvars.update({
        'environment': environment,
        'component': component,
        'deployment_id': _generate_deployment_id(),
        'managed_by': 'eos-infrastructure-compiler'
    })
    
    # Inject inter-component dependencies
    tfvars.update(_resolve_component_dependencies(component, environment))
    
    return tfvars

def _resolve_component_dependencies(component, environment):
    """Resolve dependencies between components"""
    if not HAS_SALT_UTILS:
        return {}
        
    deps = {}
    
    # Define component dependency map
    dependency_map = {
        'boundary': {
            'vault_address': 'vault:cluster_endpoint',
            'consul_address': 'consul:cluster_endpoint',
        },
        'hecate': {
            'boundary_address': 'boundary:controller_endpoint',
            'consul_address': 'consul:cluster_endpoint',
            'vault_address': 'vault:cluster_endpoint',
        },
        'hera': {
            'vault_address': 'vault:cluster_endpoint',
            'consul_address': 'consul:cluster_endpoint',
            'boundary_address': 'boundary:controller_endpoint',
        }
    }
    
    if component in dependency_map:
        consul_client = salt.utils.consul.get_conn()
        
        for var_name, dep_path in dependency_map[component].items():
            dep_component, output_key = dep_path.split(':')
            
            # Fetch from Consul
            consul_key = f'terraform/{environment}/{dep_component}/outputs/{output_key}'
            try:
                _, data = consul_client.kv.get(consul_key)
                if data and data['Value']:
                    deps[var_name] = json.loads(data['Value'].decode('utf-8'))
            except Exception as e:
                log.error(f"Failed to resolve dependency {dep_path}: {e}")
    
    return deps

def _store_outputs_in_consul(component, environment, outputs):
    """Store Terraform outputs in Consul for service discovery"""
    if not HAS_SALT_UTILS:
        return
        
    consul_client = salt.utils.consul.get_conn()
    
    for key, value in outputs.items():
        consul_key = f'terraform/{environment}/{component}/outputs/{key}'
        try:
            consul_client.kv.put(consul_key, json.dumps(value))
        except Exception as e:
            log.error(f"Failed to store output {key}: {e}")

def _verify_preconditions(component, environment):
    """Verify component dependencies are satisfied"""
    # Define component dependencies
    preconditions = {
        'vault': [],
        'consul': [],
        'boundary': ['vault', 'consul'],
        'hecate': ['vault', 'consul', 'boundary'],
        'hera': ['vault', 'consul', 'boundary'],
    }
    
    deps = preconditions.get(component, [])
    
    for dep in deps:
        if not component_is_healthy(dep, environment):
            log.error(f"Dependency {dep} is not healthy")
            return False
    
    return True

def _create_state_snapshot(component, environment):
    """Create a snapshot of the current state"""
    workspace = TerraformWorkspace(component, environment)
    state_file = workspace.workspace_path / 'terraform.tfstate'
    
    if not state_file.exists():
        return None
    
    snapshot_id = _generate_deployment_id()
    snapshot_dir = workspace.workspace_path / '.snapshots'
    snapshot_dir.mkdir(exist_ok=True)
    
    snapshot_path = snapshot_dir / f'{snapshot_id}.tfstate'
    
    import shutil
    shutil.copy2(state_file, snapshot_path)
    
    return snapshot_id

def _cleanup_consul_entries(component, environment):
    """Clean up Consul entries for a component"""
    if not HAS_SALT_UTILS:
        return
        
    consul_client = salt.utils.consul.get_conn()
    prefix = f'terraform/{environment}/{component}/'
    
    try:
        consul_client.kv.delete(prefix, recurse=True)
    except Exception as e:
        log.error(f"Failed to cleanup Consul entries: {e}")

def _store_workspace_metadata(component, environment, status):
    """Store workspace metadata in Consul"""
    if not HAS_SALT_UTILS:
        return
        
    metadata = {
        'component': component,
        'environment': environment,
        'status': status,
        'updated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'updated_by': __grains__['id']
    }
    
    consul_client = salt.utils.consul.get_conn()
    key = f'terraform/{environment}/{component}/metadata'
    
    try:
        consul_client.kv.put(key, json.dumps(metadata))
    except Exception as e:
        log.error(f"Failed to store workspace metadata: {e}")

def _update_component_metadata(component, environment, status, snapshot_id):
    """Update component metadata after operations"""
    _store_workspace_metadata(component, environment, status)
    
    if snapshot_id and HAS_SALT_UTILS:
        consul_client = salt.utils.consul.get_conn()
        key = f'terraform/{environment}/{component}/last_snapshot'
        try:
            consul_client.kv.put(key, snapshot_id)
        except Exception as e:
            log.error(f"Failed to store snapshot ID: {e}")

def _run_post_apply_hooks(component, environment, outputs):
    """Execute post-deployment configuration"""
    # Component-specific hooks can be added here
    hooks = {
        'vault': lambda: _configure_vault_post_deploy(outputs),
        'consul': lambda: _configure_consul_post_deploy(outputs),
        'boundary': lambda: _configure_boundary_post_deploy(outputs),
        'hecate': lambda: _configure_hecate_post_deploy(outputs),
        'hera': lambda: _configure_hera_post_deploy(outputs),
    }
    
    if component in hooks:
        try:
            return hooks[component]()
        except Exception as e:
            log.error(f"Post-apply hook failed for {component}: {e}")

def _configure_vault_post_deploy(outputs):
    """Configure Vault after deployment"""
    # This would contain actual Vault configuration logic
    log.info("Running Vault post-deployment configuration")

def _configure_consul_post_deploy(outputs):
    """Configure Consul after deployment"""
    log.info("Running Consul post-deployment configuration")

def _configure_boundary_post_deploy(outputs):
    """Configure Boundary after deployment"""
    log.info("Running Boundary post-deployment configuration")

def _configure_hecate_post_deploy(outputs):
    """Configure Hecate after deployment"""
    log.info("Running Hecate post-deployment configuration")

def _configure_hera_post_deploy(outputs):
    """Configure Hera after deployment"""
    log.info("Running Hera post-deployment configuration")

def _parse_plan_changes(plan_data):
    """Parse resource changes from plan data"""
    changes = []
    
    if 'resource_changes' in plan_data:
        for change in plan_data['resource_changes']:
            if change.get('change', {}).get('actions'):
                changes.append({
                    'address': change.get('address', ''),
                    'type': change.get('type', ''),
                    'name': change.get('name', ''),
                    'action': change['change']['actions']
                })
    
    return changes

def _generate_deployment_id():
    """Generate unique deployment ID"""
    timestamp = str(int(time.time() * 1000))
    host = __grains__.get('id', 'unknown')
    return hashlib.sha256(f"{timestamp}-{host}".encode()).hexdigest()[:12]