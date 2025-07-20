# Consul service registration for Helen deployments
# Ensures proper service discovery and health checking

{% set mode = salt['pillar.get']('helen:mode', 'static') %}
{% set environment = salt['pillar.get']('helen:environment', 'production') %}
{% set port = salt['pillar.get']('helen:port', 8009) %}
{% set domain = salt['pillar.get']('helen:domain') %}

# Wait for Nomad allocation to get IP address
helen_wait_for_allocation_ip:
  cmd.run:
    - name: |
        JOB_NAME="helen-{{ mode }}-{{ environment }}"
        TIMEOUT=60
        ELAPSED=0
        
        while [ $ELAPSED -lt $TIMEOUT ]; do
          # Get allocation IP from Nomad
          ALLOC_IP=$(nomad job status -json $JOB_NAME 2>/dev/null | \
            jq -r '.Allocations[0].AllocatedResources.Networks[0].IP // empty')
          
          if [ -n "$ALLOC_IP" ]; then
            echo "$ALLOC_IP" > /tmp/helen-allocation-ip.txt
            echo "Allocation IP: $ALLOC_IP"
            exit 0
          fi
          
          sleep 5
          ELAPSED=$((ELAPSED + 5))
        done
        
        echo "Failed to get allocation IP"
        exit 1
    - require:
      - sls: helen.nomad_deploy

# Register Helen service with Consul
helen_consul_service_definition:
  file.managed:
    - name: /etc/consul.d/helen-{{ mode }}-{{ environment }}.json
    - mode: 644
    - contents: |
        {
          "service": {
            "id": "helen-{{ mode }}-{{ environment }}",
            "name": "helen-{{ mode }}-{{ environment }}",
            "tags": [
              "helen",
              "{{ mode }}",
              "{{ environment }}",
              "domain:{{ domain }}",
              {% if mode == 'ghost' %}
              "cms",
              "ghost",
              {% else %}
              "static",
              "nginx",
              {% endif %}
              {% if salt['pillar.get']('helen:enable_auth', false) %}
              "auth-enabled",
              {% endif %}
              "traefik.enable=true",
              "traefik.http.routers.helen-{{ environment }}.rule=Host(`{{ domain }}`)"
            ],
            "address": "{{ salt['cmd.run']('cat /tmp/helen-allocation-ip.txt 2>/dev/null || echo 127.0.0.1') }}",
            "port": {{ port }},
            "meta": {
              "version": "{{ salt['pillar.get']('helen:git_commit', 'latest') }}",
              "deployed_at": "{{ salt['cmd.run']('date -u +%Y-%m-%dT%H:%M:%SZ') }}",
              "mode": "{{ mode }}",
              "environment": "{{ environment }}"
            },
            "checks": [
              {
                "id": "helen-{{ mode }}-{{ environment }}-http",
                "name": "HTTP Health Check",
                {% if mode == 'ghost' %}
                "http": "http://{{ salt['cmd.run']('cat /tmp/helen-allocation-ip.txt 2>/dev/null || echo 127.0.0.1') }}:{{ port }}/ghost/api/admin/site/",
                {% else %}
                "http": "http://{{ salt['cmd.run']('cat /tmp/helen-allocation-ip.txt 2>/dev/null || echo 127.0.0.1') }}:{{ port }}/",
                {% endif %}
                "method": "GET",
                "interval": "10s",
                "timeout": "5s",
                "success_before_passing": 2,
                "failures_before_critical": 3
              },
              {
                "id": "helen-{{ mode }}-{{ environment }}-tcp",
                "name": "TCP Port Check",
                "tcp": "{{ salt['cmd.run']('cat /tmp/helen-allocation-ip.txt 2>/dev/null || echo 127.0.0.1') }}:{{ port }}",
                "interval": "10s",
                "timeout": "2s"
              }
              {% if mode == 'ghost' and salt['pillar.get']('helen:database', 'mysql') == 'mysql' %},
              {
                "id": "helen-{{ mode }}-{{ environment }}-db",
                "name": "Database Connectivity",
                "script": "/usr/local/bin/check-helen-db-{{ environment }}.sh",
                "interval": "30s",
                "timeout": "10s"
              }
              {% endif %}
            ],
            "enable_tag_override": false,
            "connect": {
              "sidecar_service": {
                "proxy": {
                  "local_service_address": "127.0.0.1",
                  "local_service_port": {{ port }},
                  {% if mode == 'ghost' %}
                  "upstreams": [
                    {
                      "destination_name": "mysql",
                      "local_bind_port": 3306
                    }
                    {% if salt['pillar.get']('helen:redis:enabled', false) %},
                    {
                      "destination_name": "redis",
                      "local_bind_port": 6379
                    }
                    {% endif %}
                  ],
                  {% endif %}
                  "config": {
                    "protocol": "http"
                  }
                }
              }
            }
          }
        }
    - require:
      - cmd: helen_wait_for_allocation_ip

# Create database check script for Ghost
{% if mode == 'ghost' and salt['pillar.get']('helen:database', 'mysql') == 'mysql' %}
helen_create_db_check_script:
  file.managed:
    - name: /usr/local/bin/check-helen-db-{{ environment }}.sh
    - mode: 755
    - contents: |
        #!/bin/bash
        # Database connectivity check for Helen Ghost
        
        # Get database credentials from Vault
        DB_HOST=$(vault kv get -field=host kv/helen/{{ environment }}/database 2>/dev/null)
        DB_PORT=$(vault kv get -field=port kv/helen/{{ environment }}/database 2>/dev/null)
        DB_USER=$(vault kv get -field=user kv/helen/{{ environment }}/database 2>/dev/null)
        DB_PASS=$(vault kv get -field=password kv/helen/{{ environment }}/database 2>/dev/null)
        DB_NAME=$(vault kv get -field=database kv/helen/{{ environment }}/database 2>/dev/null)
        
        # Check if we got credentials
        if [ -z "$DB_HOST" ] || [ -z "$DB_USER" ]; then
          echo "Failed to retrieve database credentials from Vault"
          exit 2
        fi
        
        # Test database connection
        if mysqladmin ping -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASS" --silent 2>/dev/null; then
          echo "Database connection successful"
          exit 0
        else
          echo "Database connection failed"
          exit 2
        fi
    - require:
      - file: helen_consul_service_definition
{% endif %}

# Reload Consul to pick up the new service
helen_reload_consul:
  cmd.run:
    - name: consul reload
    - onlyif: systemctl is-active consul
    - require:
      - file: helen_consul_service_definition

# Verify service registration
helen_verify_consul_registration:
  cmd.run:
    - name: |
        echo "Verifying Consul service registration..."
        sleep 5  # Give Consul time to process
        
        # Check if service is registered
        if consul catalog services | grep -q "helen-{{ mode }}-{{ environment }}"; then
          echo "Service successfully registered"
          
          # Get service details
          consul catalog nodes -service=helen-{{ mode }}-{{ environment }} -detailed
          
          # Check health status
          consul watch -type=service -service=helen-{{ mode }}-{{ environment }} -once
        else
          echo "Service registration failed"
          exit 1
        fi
    - require:
      - cmd: helen_reload_consul

# Register service metadata in Consul KV
helen_consul_kv_metadata:
  consul.put:
    - name: helen/services/{{ environment }}/metadata
    - value: |
        {
          "service_name": "helen-{{ mode }}-{{ environment }}",
          "mode": "{{ mode }}",
          "environment": "{{ environment }}",
          "domain": "{{ domain }}",
          "port": {{ port }},
          "health_check_endpoints": {
            {% if mode == 'ghost' %}
            "http": "/ghost/api/admin/site/",
            "admin": "/ghost/",
            "api": "/ghost/api/v4/"
            {% else %}
            "http": "/",
            "health": "/health"
            {% endif %}
          },
          "features": {
            "authentication": {{ salt['pillar.get']('helen:enable_auth', false) | lower }},
            "ssl": true,
            "backup": {{ salt['pillar.get']('helen:backup:enabled', true) | lower }},
            "webhook": {{ salt['pillar.get']('helen:enable_webhook', false) | lower }}
          }
        }
    - require:
      - cmd: helen_verify_consul_registration

# Clean up temporary files
helen_consul_cleanup:
  file.absent:
    - names:
      - /tmp/helen-allocation-ip.txt
    - require:
      - consul: helen_consul_kv_metadata