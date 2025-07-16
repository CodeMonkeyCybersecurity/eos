# salt/states/hashicorp/nomad/service.sls
# HashiCorp Nomad service state

{% set nomad = pillar.get('nomad', {}) %}
{% set enable_service = nomad.get('enable_service', True) %}
{% set start_service = nomad.get('start_service', True) %}

# Enable and start Nomad service
{% if enable_service %}
nomad_service:
  service.running:
    - name: nomad
    - enable: True
    {% if start_service %}
    - watch:
      - file: /etc/nomad.d/nomad.hcl
      - file: /etc/systemd/system/nomad.service
    {% endif %}
    - require:
      - cmd: nomad_systemd_reload
{% endif %}

# Ensure Docker service is running (needed for Nomad container orchestration)
docker_service:
  service.running:
    - name: docker
    - enable: True
    - require:
      - pkg: docker_package