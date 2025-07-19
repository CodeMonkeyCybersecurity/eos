{#
  Salt orchestration state for deploying Hecate reverse proxy framework
  This orchestrates the complete deployment including infrastructure and services
#}

# Validate prerequisites
validate_prerequisites:
  salt.function:
    - name: eos_terraform.component_is_healthy
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - vault
      - production
    - failhard: True

# Initialize Terraform workspace for Hecate
init_hecate_workspace:
  salt.function:
    - name: eos_terraform.init_workspace
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - hecate
      - production
    - kwarg:
        backend_config:
          type: s3
          config:
            encrypt: True
    - require:
      - salt: validate_prerequisites

# Generate infrastructure variables
generate_tfvars:
  salt.function:
    - name: pillar.get
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - infrastructure:hecate
    - ret: tfvars_data

# Plan infrastructure changes
plan_hecate_infrastructure:
  salt.function:
    - name: eos_terraform.plan
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - hecate
      - production
    - kwarg:
        variables: {{ salt['pillar.get']('infrastructure:hecate', {}) | json }}
    - require:
      - salt: init_hecate_workspace

# Apply infrastructure if changes present
apply_hecate_infrastructure:
  salt.function:
    - name: eos_terraform.apply
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - hecate
      - production
    - kwarg:
        auto_approve: True
    - require:
      - salt: plan_hecate_infrastructure
    - onlyif:
      - fun: eos_terraform.plan
        args:
          - hecate
          - production
        kwargs:
          variables: {{ salt['pillar.get']('infrastructure:hecate', {}) | json }}
        changes_present: True

# Wait for instances to be ready
wait_for_instances:
  salt.wait_for_event:
    - name: salt/minion/*/start
    - id_list:
      - 'hecate-production-*'
    - timeout: 300
    - require:
      - salt: apply_hecate_infrastructure

# Configure base system on all Hecate nodes
configure_hecate_base:
  salt.state:
    - tgt: 'roles:hecate'
    - tgt_type: grain
    - sls:
      - hecate.base
      - consul.agent
      - nomad.client
    - require:
      - salt: wait_for_instances

# Deploy PostgreSQL
deploy_postgres:
  salt.function:
    - name: nomad.job_run
    - tgt: 'roles:nomad-server'
    - tgt_type: grain
    - arg:
      - /srv/nomad/jobs/postgres.nomad
    - kwarg:
        variables:
          postgres_password: {{ salt['vault.read_secret']('secret/services/postgres/admin')['data']['password'] }}
          grafana_db_password: {{ salt['vault.read_secret']('secret/services/postgres/grafana')['data']['password'] }}
          authentik_db_password: {{ salt['vault.read_secret']('secret/services/postgres/authentik')['data']['password'] }}
          mattermost_db_password: {{ salt['vault.read_secret']('secret/services/postgres/mattermost')['data']['password'] }}
          wazuh_db_password: {{ salt['vault.read_secret']('secret/services/postgres/wazuh')['data']['password'] }}
    - require:
      - salt: configure_hecate_base

# Deploy Redis
deploy_redis:
  salt.function:
    - name: nomad.job_run
    - tgt: 'roles:nomad-server'
    - tgt_type: grain
    - arg:
      - /srv/nomad/jobs/redis.nomad
    - kwarg:
        variables:
          redis_password: {{ salt['vault.read_secret']('secret/services/redis')['data']['password'] }}
    - require:
      - salt: configure_hecate_base

# Wait for databases to be ready
wait_for_databases:
  salt.wait_for_event:
    - name: consul/service/*/healthy
    - id_list:
      - postgres
      - redis
    - timeout: 180
    - require:
      - salt: deploy_postgres
      - salt: deploy_redis

# Deploy Authentik
deploy_authentik:
  salt.state:
    - tgt: 'roles:hecate'
    - tgt_type: grain
    - sls:
      - hecate.authentik
    - require:
      - salt: wait_for_databases

# Deploy Caddy
deploy_caddy:
  salt.state:
    - tgt: 'roles:hecate'
    - tgt_type: grain
    - sls:
      - hecate.caddy
    - require:
      - salt: deploy_authentik

# Configure integration
configure_integration:
  salt.state:
    - tgt: 'roles:hecate'
    - tgt_type: grain
    - sls:
      - hecate.integration
    - require:
      - salt: deploy_caddy

# Deploy requested services
{% if pillar.get('hecate:services', []) %}
deploy_services:
  salt.parallel:
    - require:
      - salt: configure_integration
  {% for service in pillar.get('hecate:services', []) %}
    - deploy_{{ service }}:
        salt.function:
          - name: nomad.job_run
          - tgt: 'roles:nomad-server'
          - tgt_type: grain
          - arg:
            - /srv/nomad/jobs/{{ service }}.nomad
          - kwarg:
              variables: {{ salt['pillar.get']('services:' + service + ':variables', {}) | json }}
  {% endfor %}
{% endif %}

# Configure monitoring
configure_monitoring:
  salt.state:
    - tgt: 'roles:hecate'
    - tgt_type: grain
    - sls:
      - monitoring.exporters
      - monitoring.promtail
    - require:
      - salt: deploy_services

# Run health checks
run_health_checks:
  salt.function:
    - name: hecate.health_check
    - tgt: 'roles:hecate'
    - tgt_type: grain
    - require:
      - salt: configure_monitoring

# Store deployment metadata
store_deployment_metadata:
  salt.function:
    - name: consul.put
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - hecate/deployment/metadata
    - kwarg:
        value:
          deployment_id: {{ salt['grains.get']('deployment_id', 'unknown') }}
          timestamp: {{ salt['cmd.run']('date -u +"%Y-%m-%dT%H:%M:%SZ"') }}
          services: {{ pillar.get('hecate:services', []) | json }}
          status: deployed
    - require:
      - salt: run_health_checks

# Send notification
send_notification:
  salt.function:
    - name: slack.post_message
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - '#deployments'
      - 'Hecate deployment completed successfully'
    - kwarg:
        color: good
        fields:
          Environment: production
          Services: {{ pillar.get('hecate:services', []) | join(', ') }}
          Status: Deployed
    - require:
      - salt: store_deployment_metadata
    - onfail_in:
      - salt: send_failure_notification

# Failure notification
send_failure_notification:
  salt.function:
    - name: slack.post_message
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - '#deployments'
      - 'Hecate deployment failed'
    - kwarg:
        color: danger
        fields:
          Environment: production
          Error: Check Salt event bus for details