{#
  Salt orchestration state for deploying Boundary
#}

# Validate dependencies
validate_boundary_dependencies:
  salt.runner:
    - name: salt.cmd
    - arg:
      - orch.common.validate
    - failhard: True

# Initialize Terraform workspace
init_boundary_workspace:
  salt.function:
    - name: eos_terraform.init_workspace
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - boundary
      - production
    - kwarg:
        backend_config:
          type: s3
          config:
            encrypt: True
    - require:
      - salt: validate_boundary_dependencies

# Plan infrastructure
plan_boundary_infrastructure:
  salt.function:
    - name: eos_terraform.plan
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - boundary
      - production
    - kwarg:
        variables: {{ salt['pillar.get']('infrastructure:boundary', {}) | json }}
    - require:
      - salt: init_boundary_workspace

# Apply infrastructure
apply_boundary_infrastructure:
  salt.function:
    - name: eos_terraform.apply
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - boundary
      - production
    - kwarg:
        auto_approve: True
    - require:
      - salt: plan_boundary_infrastructure

# Get outputs
get_boundary_outputs:
  salt.function:
    - name: eos_terraform.get_outputs
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - boundary
      - production
    - ret: boundary_outputs
    - require:
      - salt: apply_boundary_infrastructure

# Wait for instances
wait_for_boundary_instances:
  salt.wait_for_event:
    - name: salt/minion/*/start
    - id_list:
      - 'boundary-production-*'
    - timeout: 300
    - require:
      - salt: apply_boundary_infrastructure

# Initialize database
initialize_boundary_database:
  salt.state:
    - tgt: 'boundary-production-controller-1'
    - sls:
      - boundary.database
    - require:
      - salt: wait_for_boundary_instances

# Configure controllers
configure_boundary_controllers:
  salt.state:
    - tgt: 'boundary-production-controller-*'
    - tgt_type: glob
    - sls:
      - boundary.controller
    - require:
      - salt: initialize_boundary_database

# Configure workers
configure_boundary_workers:
  salt.state:
    - tgt: 'boundary-production-worker-*'
    - tgt_type: glob
    - sls:
      - boundary.worker
    - require:
      - salt: configure_boundary_controllers

# Configure organizations
configure_boundary_orgs:
  salt.state:
    - tgt: 'boundary-production-controller-1'
    - sls:
      - boundary.organizations
    - require:
      - salt: configure_boundary_workers

# Configure auth methods
configure_boundary_auth:
  salt.state:
    - tgt: 'boundary-production-controller-1'
    - sls:
      - boundary.auth_methods
    - require:
      - salt: configure_boundary_orgs

# Configure hosts and targets
configure_boundary_targets:
  salt.state:
    - tgt: 'boundary-production-controller-1'
    - sls:
      - boundary.targets
    - require:
      - salt: configure_boundary_auth

# Run health checks
boundary_health_check:
  salt.function:
    - name: http.query
    - tgt: 'boundary-production-controller-*'
    - tgt_type: glob
    - arg:
      - http://localhost:9200/v1/health
    - require:
      - salt: configure_boundary_targets

# Store metadata
store_boundary_metadata:
  salt.function:
    - name: consul.put
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - boundary/cluster/metadata
    - kwarg:
        value:
          controller_endpoint: {{ salt['pillar.get']('boundary_outputs:controller_endpoint', '') }}
          worker_count: {{ salt['pillar.get']('infrastructure:boundary:worker_count', 3) }}
          status: healthy
    - require:
      - salt: boundary_health_check