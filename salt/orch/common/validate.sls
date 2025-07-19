{#
  Common validation orchestration state
  Validates prerequisites for infrastructure deployments
#}

# Check Salt master connectivity
check_salt_master:
  salt.function:
    - name: test.ping
    - tgt: '*'

# Validate Vault connectivity
validate_vault:
  salt.function:
    - name: vault.is_initialized
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - failhard: True

# Check Vault seal status
check_vault_seal:
  salt.function:
    - name: cmd.run
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - 'vault status -format=json | jq -r .sealed'
    - check_cmd:
      - test "$result" = "false"
    - failhard: True
    - require:
      - salt: validate_vault

# Validate Consul cluster
validate_consul:
  salt.function:
    - name: consul.list_nodes
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - failhard: True

# Check Consul leader
check_consul_leader:
  salt.function:
    - name: consul.leader
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - failhard: True
    - require:
      - salt: validate_consul

# Validate Nomad cluster
validate_nomad:
  salt.function:
    - name: nomad.status
    - tgt: 'roles:nomad-server'
    - tgt_type: grain
    - failhard: True

# Check Nomad leader
check_nomad_leader:
  salt.function:
    - name: cmd.run
    - tgt: 'roles:nomad-server'
    - tgt_type: grain
    - arg:
      - 'nomad server members -json | jq -r ".[] | select(.Leader == true) | .Name"'
    - failhard: True
    - require:
      - salt: validate_nomad

# Validate AWS credentials
validate_aws_credentials:
  salt.function:
    - name: boto3.get_caller_identity
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - failhard: True

# Check Terraform installation
check_terraform:
  salt.function:
    - name: cmd.which
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - terraform
    - failhard: True

# Validate network connectivity
validate_network:
  salt.function:
    - name: network.ping
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - consul.service.consul
    - failhard: True

# Check disk space
check_disk_space:
  salt.function:
    - name: disk.usage
    - tgt: '*'
    - check_cmd:
      - test $(echo "$result" | jq -r '."/".percent' | cut -d. -f1) -lt 80
    - failhard: True

# Validate required secrets exist
validate_secrets:
  salt.parallel:
    - failhard: True
    - require:
      - salt: check_vault_seal
    - postgres_admin:
        salt.function:
          - name: vault.read_secret
          - tgt: 'roles:salt-master'
          - tgt_type: grain
          - arg:
            - secret/services/postgres/admin
    - redis_password:
        salt.function:
          - name: vault.read_secret
          - tgt: 'roles:salt-master'
          - tgt_type: grain
          - arg:
            - secret/services/redis
    - authentik_secret:
        salt.function:
          - name: vault.read_secret
          - tgt: 'roles:salt-master'
          - tgt_type: grain
          - arg:
            - secret/services/authentik
    - caddy_credentials:
        salt.function:
          - name: vault.read_secret
          - tgt: 'roles:salt-master'
          - tgt_type: grain
          - arg:
            - secret/services/caddy

# Summary report
validation_summary:
  salt.function:
    - name: test.echo
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - "All validation checks passed successfully"
    - require:
      - salt: check_salt_master
      - salt: check_vault_seal
      - salt: check_consul_leader
      - salt: check_nomad_leader
      - salt: validate_aws_credentials
      - salt: check_terraform
      - salt: validate_network
      - salt: check_disk_space
      - salt: validate_secrets