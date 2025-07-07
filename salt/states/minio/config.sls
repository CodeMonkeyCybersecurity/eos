# salt/states/minio/config.sls
# MinIO configuration management

{% set minio = pillar.get('minio', {}) %}
{% set minio_user = minio.get('user', 'minio') %}
{% set minio_group = minio.get('group', 'minio') %}
{% set config_path = minio.get('config_path', '/etc/minio') %}
{% set data_path = minio.get('data_path', '/var/lib/minio') %}
{% set api_port = minio.get('api_port', 9123) %}
{% set console_port = minio.get('console_port', 9124) %}

# MinIO environment configuration
minio_environment_config:
  file.managed:
    - name: {{ config_path }}/minio.env
    - contents: |
        # MinIO Configuration
        MINIO_DATA_DIR={{ data_path }}/data
        MINIO_VOLUMES={{ data_path }}/data
        MINIO_OPTS=--console-address :{{ console_port }}
        MINIO_API_PORT={{ api_port }}
        MINIO_CONSOLE_PORT={{ console_port }}
        
        # Logging
        MINIO_LOG_FILE={{ minio.get('log_path', '/var/log/minio') }}/minio.log
        
        # Prometheus monitoring
        MINIO_PROMETHEUS_URL=http://prometheus.service.consul:9090
        MINIO_PROMETHEUS_JOB_ID=minio
        
        # Browser redirect URL for console
        MINIO_BROWSER_REDIRECT_URL=http://localhost:{{ console_port }}
    - user: {{ minio_user }}
    - group: {{ minio_group }}
    - mode: 640
    - makedirs: True
    - require:
      - file: minio_directories

# Docker Compose configuration for MinIO
minio_docker_compose:
  file.managed:
    - name: /opt/minio/docker-compose.yml
    - contents: |
        version: '3.8'
        
        services:
          minio:
            image: minio/minio:latest
            container_name: minio
            restart: unless-stopped
            environment:
              # Credentials will be loaded from Vault
              MINIO_ROOT_USER: ${MINIO_ROOT_USER}
              MINIO_ROOT_PASSWORD: ${MINIO_ROOT_PASSWORD}
              MINIO_PROMETHEUS_URL: http://prometheus.service.consul:9090
              MINIO_PROMETHEUS_JOB_ID: minio
              MINIO_BROWSER_REDIRECT_URL: http://localhost:{{ console_port }}
            ports:
              - "{{ api_port }}:9000"
              - "{{ console_port }}:9001"
            volumes:
              - {{ data_path }}/data:/data
            command: server /data --console-address ":9001"
            healthcheck:
              test: ["CMD", "curl", "-f", "http://localhost:9000/minio/health/live"]
              interval: 30s
              timeout: 20s
              retries: 3
            labels:
              - "prometheus.io/scrape=true"
              - "prometheus.io/port=9000"
              - "prometheus.io/path=/minio/v2/metrics/cluster"
              
        networks:
          default:
            name: minio_network
    - user: {{ minio_user }}
    - group: {{ minio_group }}
    - mode: 644
    - require:
      - file: minio_directories

# MinIO startup script
minio_startup_script:
  file.managed:
    - name: /opt/minio/start-minio.sh
    - contents: |
        #!/bin/bash
        # MinIO startup script with Vault integration
        
        set -e
        
        # Source environment
        source {{ config_path }}/minio.env
        
        # Check if Vault is available and get credentials
        if command -v vault >/dev/null 2>&1; then
            echo "Getting MinIO credentials from Vault..."
            if vault kv get -format=json kv/minio/root >/dev/null 2>&1; then
                export MINIO_ROOT_USER=$(vault kv get -field=MINIO_ROOT_USER kv/minio/root)
                export MINIO_ROOT_PASSWORD=$(vault kv get -field=MINIO_ROOT_PASSWORD kv/minio/root)
                echo "Credentials loaded from Vault"
            else
                echo "Warning: Could not load credentials from Vault"
                echo "Using default credentials (change these immediately!)"
                export MINIO_ROOT_USER=${MINIO_ROOT_USER:-minioadmin}
                export MINIO_ROOT_PASSWORD=${MINIO_ROOT_PASSWORD:-minioadmin}
            fi
        else
            echo "Warning: Vault not available"
            echo "Using default credentials (change these immediately!)"
            export MINIO_ROOT_USER=${MINIO_ROOT_USER:-minioadmin}
            export MINIO_ROOT_PASSWORD=${MINIO_ROOT_PASSWORD:-minioadmin}
        fi
        
        # Start MinIO using Docker Compose
        cd /opt/minio
        docker-compose up -d
        
        echo "MinIO started successfully"
        echo "API available at: http://localhost:{{ api_port }}"
        echo "Console available at: http://localhost:{{ console_port }}"
    - user: {{ minio_user }}
    - group: {{ minio_group }}
    - mode: 755
    - require:
      - file: minio_docker_compose

# MinIO stop script
minio_stop_script:
  file.managed:
    - name: /opt/minio/stop-minio.sh
    - contents: |
        #!/bin/bash
        # MinIO stop script
        
        cd /opt/minio
        docker-compose down
        echo "MinIO stopped"
    - user: {{ minio_user }}
    - group: {{ minio_group }}
    - mode: 755
    - require:
      - file: minio_docker_compose