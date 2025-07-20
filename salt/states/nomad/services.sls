# Nomad Services State
# Manages containerized services via SaltStack → Terraform → Nomad pattern

{% set service_name = pillar.get('nomad_service:name', 'jenkins') %}
{% set environment = pillar.get('nomad_service:environment', 'production') %}
{% set service_config = pillar.get('nomad_service:config', {}) %}

# Deploy containerized service via Terraform → Nomad
deploy_nomad_service_{{ service_name }}:
  eos_terraform.deploy_nomad_service:
    - service_name: {{ service_name }}
    - environment: {{ environment }}
    - service_config: {{ service_config | json }}
    - auto_approve: True

# Wait for service to be healthy
wait_for_{{ service_name }}_health:
  cmd.run:
    - name: |
        for i in {1..30}; do
          if consul catalog services | grep -q "{{ service_name }}"; then
            echo "{{ service_name }} is registered in Consul"
            exit 0
          fi
          sleep 2
        done
        echo "{{ service_name }} failed to register within timeout"
        exit 1
    - require:
      - eos_terraform: deploy_nomad_service_{{ service_name }}

# Output service information
service_{{ service_name }}_info:
  cmd.run:
    - name: |
        echo "Service {{ service_name }} deployed successfully"
        echo "Access URL: http://localhost:{{ service_config.get('port', 8080) }}"
        echo "Consul Service: {{ service_name }}.service.consul"
        echo "Nomad Job: {{ service_name }}"
    - require:
      - cmd: wait_for_{{ service_name }}_health