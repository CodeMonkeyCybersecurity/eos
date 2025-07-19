{#
  Salt orchestration state for deploying Consul cluster
#}

# Initialize Terraform workspace for Consul
init_consul_workspace:
  salt.function:
    - name: eos_terraform.init_workspace
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - consul
      - production
    - kwarg:
        backend_config:
          type: s3
          config:
            encrypt: True

# Plan Consul infrastructure
plan_consul_infrastructure:
  salt.function:
    - name: eos_terraform.plan
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - consul
      - production
    - kwarg:
        variables: {{ salt['pillar.get']('infrastructure:consul', {}) | json }}
    - require:
      - salt: init_consul_workspace

# Apply Consul infrastructure
apply_consul_infrastructure:
  salt.function:
    - name: eos_terraform.apply
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - consul
      - production
    - kwarg:
        auto_approve: True
    - require:
      - salt: plan_consul_infrastructure

# Get Terraform outputs
get_consul_outputs:
  salt.function:
    - name: eos_terraform.get_outputs
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - consul
      - production
    - ret: consul_outputs
    - require:
      - salt: apply_consul_infrastructure

# Wait for Consul instances
wait_for_consul_instances:
  salt.wait_for_event:
    - name: salt/minion/*/start
    - id_list:
      - 'consul-production-*'
    - timeout: 300
    - require:
      - salt: apply_consul_infrastructure

# Bootstrap Consul cluster
bootstrap_consul:
  salt.state:
    - tgt: 'consul-production-*'
    - tgt_type: glob
    - sls:
      - consul.server
    - require:
      - salt: wait_for_consul_instances

# Wait for cluster formation
wait_for_cluster:
  salt.function:
    - name: consul.leader
    - tgt: 'consul-production-*'
    - tgt_type: glob
    - retry:
        attempts: 10
        until: True
        interval: 10
    - require:
      - salt: bootstrap_consul

# Configure ACL system
configure_consul_acl:
  salt.state:
    - tgt: 'consul-production-*'
    - tgt_type: glob
    - batch: 1
    - sls:
      - consul.acl
    - require:
      - salt: wait_for_cluster

# Configure Consul Connect
configure_consul_connect:
  salt.state:
    - tgt: 'consul-production-*'
    - tgt_type: glob
    - sls:
      - consul.connect
    - require:
      - salt: configure_consul_acl

# Configure intentions
configure_intentions:
  salt.state:
    - tgt: 'consul-production-*'
    - tgt_type: glob
    - batch: 1
    - sls:
      - consul.intentions
    - require:
      - salt: configure_consul_connect

# Configure prepared queries
configure_prepared_queries:
  salt.state:
    - tgt: 'consul-production-*'
    - tgt_type: glob
    - batch: 1
    - sls:
      - consul.queries
    - require:
      - salt: configure_intentions

# Run health checks
consul_health_check:
  salt.function:
    - name: consul.list_nodes
    - tgt: 'consul-production-*'
    - tgt_type: glob
    - require:
      - salt: configure_prepared_queries

# Store cluster information
store_consul_metadata:
  salt.function:
    - name: consul.put
    - tgt: 'roles:salt-master'
    - tgt_type: grain
    - arg:
      - consul/cluster/metadata
    - kwarg:
        value:
          cluster_endpoint: {{ salt['pillar.get']('consul_outputs:cluster_endpoint', '') }}
          cluster_size: {{ salt['pillar.get']('infrastructure:consul:cluster_size', 3) }}
          datacenter: dc1
          status: healthy
    - require:
      - salt: consul_health_check