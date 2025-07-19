# Salt state for managing authentication policies
{% set policy = salt['pillar.get']('hecate_auth_policy', {}) %}

{% if policy %}
# Store policy configuration in Consul
consul_store_policy_{{ policy.name | replace(' ', '_') }}:
  cmd.run:
    - name: |
        consul kv put hecate/auth-policies/{{ policy.name }} '{{ policy | tojson }}'
    - require:
      - service: consul

# Create Authentik policy via API (requires Authentik to be running)
{% set authentik_url = salt['pillar.get']('hecate:authentik_url', 'http://localhost:9000') %}
{% set api_token = salt['vault'].read_secret('secret/hecate/authentik/api_token', 'token') %}

authentik_policy_{{ policy.name | replace(' ', '_') }}:
  http.query:
    - name: {{ authentik_url }}/api/v3/policies/expression/
    - method: POST
    - header_dict:
        Authorization: "Bearer {{ api_token }}"
        Content-Type: "application/json"
    - data: |
        {
          "name": "{{ policy.name }}",
          "slug": "{{ policy.name | lower | replace(' ', '-') }}",
          "enabled": true,
          "expression": "{% if policy.groups %}return request.user.groups.filter(name__in={{ policy.groups | tojson }}).exists(){% if policy.require_mfa %} and request.user.mfa_devices.exists(){% endif %}{% elif policy.require_mfa %}return request.user.mfa_devices.exists(){% else %}return True{% endif %}"
        }
    - status: 201
    - require:
      - service: authentik

# Create group-based policy bindings if specified
{% if policy.groups %}
{% for group in policy.groups %}
authentik_group_policy_binding_{{ policy.name | replace(' ', '_') }}_{{ group | replace(' ', '_') }}:
  http.query:
    - name: {{ authentik_url }}/api/v3/policies/bindings/
    - method: POST
    - header_dict:
        Authorization: "Bearer {{ api_token }}"
        Content-Type: "application/json"
    - data: |
        {
          "policy": "{{ policy.name | lower | replace(' ', '-') }}",
          "group": "{{ group }}",
          "enabled": true,
          "order": 0
        }
    - status: 201
    - require:
      - http: authentik_policy_{{ policy.name | replace(' ', '_') }}
{% endfor %}
{% endif %}

{% else %}
auth_policy_pillar_warning:
  test.show_notification:
    - text: "No auth policy configuration found in pillar data"
{% endif %}