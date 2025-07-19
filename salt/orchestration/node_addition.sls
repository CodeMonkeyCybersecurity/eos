# salt/orchestration/node_addition.sls
# Orchestration for adding a new node to the cluster

{% set new_node = salt.pillar.get('new_node') %}
{% set current_nodes = salt['mine.get']('*', 'node_info') %}

# Step 1: Accept new node's key
accept_new_node_key:
  salt.wheel:
    - name: key.accept
    - match: {{ new_node.hostname }}

# Step 2: Wait for node to be reachable
wait_for_node:
  salt.wait_for_event:
    - name: salt/minion/{{ new_node.hostname }}/start
    - timeout: 60

# Step 3: Calculate new role distribution
{% set cluster_size = current_nodes|length + 1 %}
{% set new_scale = 'single' %}
{% if cluster_size == 2 %}
  {% set new_scale = 'small' %}
{% elif cluster_size <= 6 %}
  {% set new_scale = 'medium' %}
{% else %}
  {% set new_scale = 'distributed' %}
{% endif %}

# Step 4: Update role assignments based on cluster size
{% if cluster_size == 2 %}
  # Two nodes: edge and core
  assign_edge_role:
    salt.state:
      - tgt: {{ current_nodes.keys()|first }}
      - sls:
        - roles.edge
        - storage.config
      - pillar:
          role: edge
          scale: small

  assign_core_role:
    salt.state:
      - tgt: {{ new_node.hostname }}
      - sls:
        - roles.core
        - storage.config
      - pillar:
          role: core
          scale: small

{% elif cluster_size == 3 %}
  # Three nodes: edge, core, data
  {% set nodes = current_nodes.keys()|list + [new_node.hostname] %}
  assign_three_node_roles:
    salt.state:
      - tgt: {{ nodes[0] }}
      - sls:
        - roles.edge
        - storage.config
      - pillar:
          role: edge
          scale: small

  assign_core_to_second:
    salt.state:
      - tgt: {{ nodes[1] }}
      - sls:
        - roles.core
        - storage.config
      - pillar:
          role: core
          scale: small

  assign_data_to_third:
    salt.state:
      - tgt: {{ nodes[2] }}
      - sls:
        - roles.data
        - storage.config
      - pillar:
          role: data
          scale: small

{% else %}
  # 4+ nodes: Run role calculation module
  calculate_roles:
    salt.runner:
      - name: eos_roles.calculate_distribution
      - cluster_size: {{ cluster_size }}
      - new_node: {{ new_node.hostname }}

  # Apply calculated roles
  apply_calculated_roles:
    salt.state:
      - tgt: '*'
      - sls:
        - roles.dynamic
        - storage.config
      - pillar:
          scale: {{ new_scale }}
{% endif %}

# Step 5: Update storage thresholds on all nodes
update_storage_thresholds:
  salt.state:
    - tgt: '*'
    - sls: storage.thresholds
    - pillar:
        scale: {{ new_scale }}
        node_count: {{ cluster_size }}

# Step 6: Restart storage monitoring on all nodes
restart_storage_monitoring:
  salt.cmd.run:
    - tgt: '*'
    - name: systemctl restart eos-storage-monitor

# Step 7: Update cluster configuration
update_cluster_config:
  salt.state:
    - tgt: '*'
    - sls: cluster.config
    - pillar:
        cluster_size: {{ cluster_size }}
        cluster_scale: {{ new_scale }}