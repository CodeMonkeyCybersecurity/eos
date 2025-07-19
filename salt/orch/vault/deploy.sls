{#
  Salt orchestration state for deploying Vault cluster
#}

# Initialize Terraform workspace for Vault
init_vault_workspace:
  salt.function:
    - name: eos_terraform.init_workspace
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - vault
      - production
    - kwarg:
        backend_config:
          type: s3
          config:
            encrypt: True

# Plan Vault infrastructure
plan_vault_infrastructure:
  salt.function:
    - name: eos_terraform.plan
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - vault
      - production
    - kwarg:
        variables: {{ salt['pillar.get']('infrastructure:vault', {}) | json }}
    - require:
      - salt: init_vault_workspace

# Apply Vault infrastructure
apply_vault_infrastructure:
  salt.function:
    - name: eos_terraform.apply
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - vault
      - production
    - kwarg:
        auto_approve: True
    - require:
      - salt: plan_vault_infrastructure

# Get Terraform outputs
get_vault_outputs:
  salt.function:
    - name: eos_terraform.get_outputs
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - vault
      - production
    - ret: vault_outputs
    - require:
      - salt: apply_vault_infrastructure

# Wait for Vault instances
wait_for_vault_instances:
  salt.wait_for_event:
    - name: salt/minion/*/start
    - id_list:
      - 'vault-production-*'
    - timeout: 300
    - require:
      - salt: apply_vault_infrastructure

# Initialize first Vault node
initialize_vault:
  salt.state:
    - tgt: 'vault-production-*'
    - tgt_type: glob
    - batch: 1
    - sls:
      - vault.initialize
    - require:
      - salt: wait_for_vault_instances

# Join remaining nodes to cluster
join_vault_cluster:
  salt.state:
    - tgt: 'vault-production-*'
    - tgt_type: glob
    - sls:
      - vault.join_raft
    - require:
      - salt: initialize_vault

# Configure Vault policies
configure_vault_policies:
  salt.state:
    - tgt: 'roles:vault and G@vault_initialized:true'
    - tgt_type: compound
    - batch: 1
    - sls:
      - vault.policies
    - require:
      - salt: join_vault_cluster

# Configure auth methods
configure_vault_auth:
  salt.state:
    - tgt: 'roles:vault and G@vault_initialized:true'
    - tgt_type: compound
    - batch: 1
    - sls:
      - vault.auth
    - require:
      - salt: configure_vault_policies

# Configure secrets engines
configure_vault_secrets:
  salt.state:
    - tgt: 'roles:vault and G@vault_initialized:true'
    - tgt_type: compound
    - batch: 1
    - sls:
      - vault.secrets_engines
    - require:
      - salt: configure_vault_auth

# Configure audit logging
configure_vault_audit:
  salt.state:
    - tgt: 'roles:vault and G@vault_initialized:true'
    - tgt_type: compound
    - batch: 1
    - sls:
      - vault.audit
    - require:
      - salt: configure_vault_secrets

# Run health checks
vault_health_check:
  salt.function:
    - name: vault.is_initialized
    - tgt: 'vault-production-*'
    - tgt_type: glob
    - require:
      - salt: configure_vault_audit

# Store cluster information
store_vault_metadata:
  salt.function:
    - name: consul.put
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - vault/cluster/metadata
    - kwarg:
        value:
          cluster_endpoint: {{ salt['pillar.get']('vault_outputs:cluster_endpoint', '') }}
          kms_key_id: {{ salt['pillar.get']('vault_outputs:kms_key_id', '') }}
          backup_bucket: {{ salt['pillar.get']('vault_outputs:backup_bucket', '') }}
          initialized: true
          sealed: false
    - require:
      - salt: vault_health_check