# salt/reactor/node_join.sls
# Reactor for handling new node join events

{% set hostname = data['id'] %}
{% set event_data = data['data'] %}

# Log the event
log_node_join:
  local.cmd.run:
    - tgt: {{ data['id'] }}
    - arg:
      - 'logger "EOS: Node {{ hostname }} joining cluster"'

# Register the node if it's new
register_new_node:
  local.eos_cluster.register_node:
    - tgt: {{ data['_stamp'] }}
    - kwarg:
        node_data:
          hostname: {{ hostname }}
          ip: {{ event_data.get('ip', 'unknown') }}
          resources: {{ event_data.get('resources', {}) }}

# For accepted nodes, trigger orchestration
{% if event_data.get('event_type') == 'accepted' %}
trigger_role_assignment:
  runner.state.orchestrate:
    - args:
      - orchestration.node_addition
    - pillar:
        new_node:
          hostname: {{ hostname }}
          ip: {{ event_data.get('ip', '') }}
{% endif %}