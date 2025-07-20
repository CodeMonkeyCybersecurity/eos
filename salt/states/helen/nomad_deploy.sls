# Nomad deployment orchestration for Helen
# Handles job templating and deployment for both static and Ghost modes

{% set mode = salt['pillar.get']('helen:mode', 'static') %}
{% set environment = salt['pillar.get']('helen:environment', 'production') %}
{% set namespace = salt['pillar.get']('helen:namespace', 'helen') %}

# Create Nomad job directory
helen_nomad_job_directory:
  file.directory:
    - name: /opt/eos/nomad/jobs/helen
    - mode: 755
    - makedirs: True

# Generate Nomad job file from template
helen_generate_nomad_job:
  file.managed:
    - name: /opt/eos/nomad/jobs/helen/helen-{{ mode }}-{{ environment }}.nomad
    - source: salt://helen/files/helen-{{ mode }}.nomad.jinja
    - template: jinja
    - mode: 644
    - defaults:
        mode: {{ mode }}
        environment: {{ environment }}
        namespace: {{ namespace }}
        port: {{ salt['pillar.get']('helen:port', 8009) }}
        domain: {{ salt['pillar.get']('helen:domain') }}
        instance_count: {{ salt['pillar.get']('helen:instance_count', 1) }}
        docker_image: {{ salt['pillar.get']('helen:docker_image', 'nginx:alpine' if mode == 'static' else 'ghost:5-alpine') }}
        cpu: {{ salt['pillar.get']('helen:cpu', 500) }}
        memory: {{ salt['pillar.get']('helen:memory', 128 if mode == 'static' else 512) }}
        enable_auth: {{ salt['pillar.get']('helen:enable_auth', false) }}
        database: {{ salt['pillar.get']('helen:database', 'mysql') }}
        git_commit: {{ salt['pillar.get']('helen:git_commit', 'latest') }}
    - require:
      - file: helen_nomad_job_directory
      - sls: helen.vault_secrets
      - sls: helen.docker_image
      - sls: helen.volumes

# Validate the Nomad job file
helen_validate_nomad_job:
  cmd.run:
    - name: nomad job validate /opt/eos/nomad/jobs/helen/helen-{{ mode }}-{{ environment }}.nomad
    - require:
      - file: helen_generate_nomad_job

# Check if job already exists and get its status
helen_check_existing_job:
  cmd.run:
    - name: |
        if nomad job status helen-{{ mode }}-{{ environment }} 2>/dev/null; then
          echo "EXISTS"
          # Get current allocation count
          nomad job status -json helen-{{ mode }}-{{ environment }} | \
            jq -r '.TaskGroups[0].Count // 0' > /tmp/helen-current-count
        else
          echo "NOT_EXISTS"
          echo "0" > /tmp/helen-current-count
        fi
    - require:
      - cmd: helen_validate_nomad_job

# Plan the Nomad job deployment
helen_plan_nomad_deployment:
  cmd.run:
    - name: |
        nomad job plan -diff \
          /opt/eos/nomad/jobs/helen/helen-{{ mode }}-{{ environment }}.nomad \
          > /tmp/helen-deployment-plan.txt 2>&1 || true
        cat /tmp/helen-deployment-plan.txt
    - require:
      - cmd: helen_check_existing_job

# Deploy or update the Nomad job
helen_deploy_nomad_job:
  cmd.run:
    - name: |
        # Check if this is an update or new deployment
        CURRENT_COUNT=$(cat /tmp/helen-current-count)
        TARGET_COUNT={{ salt['pillar.get']('helen:instance_count', 1) }}
        
        # Run the job
        if [ "$CURRENT_COUNT" -gt "0" ]; then
          echo "Updating existing job..."
          nomad job run -check-index 0 \
            /opt/eos/nomad/jobs/helen/helen-{{ mode }}-{{ environment }}.nomad
        else
          echo "Deploying new job..."
          nomad job run \
            /opt/eos/nomad/jobs/helen/helen-{{ mode }}-{{ environment }}.nomad
        fi
    - require:
      - cmd: helen_plan_nomad_deployment

# Wait for deployment to complete
helen_wait_for_deployment:
  cmd.run:
    - name: |
        echo "Waiting for deployment to complete..."
        JOB_NAME="helen-{{ mode }}-{{ environment }}"
        TIMEOUT=300  # 5 minutes
        ELAPSED=0
        
        while [ $ELAPSED -lt $TIMEOUT ]; do
          # Get deployment status
          STATUS=$(nomad job status -json $JOB_NAME 2>/dev/null | \
            jq -r '.Status // "pending"')
          
          # Check allocations
          RUNNING=$(nomad job status -json $JOB_NAME 2>/dev/null | \
            jq -r '.TaskGroups[0].Summary.Running // 0')
          DESIRED={{ salt['pillar.get']('helen:instance_count', 1) }}
          
          echo "Status: $STATUS, Running: $RUNNING/$DESIRED"
          
          if [ "$STATUS" = "running" ] && [ "$RUNNING" -eq "$DESIRED" ]; then
            echo "Deployment completed successfully!"
            exit 0
          fi
          
          if [ "$STATUS" = "dead" ] || [ "$STATUS" = "failed" ]; then
            echo "Deployment failed with status: $STATUS"
            exit 1
          fi
          
          sleep 10
          ELAPSED=$((ELAPSED + 10))
        done
        
        echo "Deployment timeout after ${TIMEOUT} seconds"
        exit 1
    - require:
      - cmd: helen_deploy_nomad_job
    - retry:
        attempts: 3
        interval: 30

# Get allocation information for the deployment
helen_get_allocation_info:
  cmd.run:
    - name: |
        JOB_NAME="helen-{{ mode }}-{{ environment }}"
        echo "Getting allocation information for $JOB_NAME..."
        
        # Get allocations
        ALLOCS=$(nomad job status -json $JOB_NAME | \
          jq -r '.Allocations[] | "\(.ID) \(.NodeID) \(.ClientStatus)"')
        
        echo "Allocations:"
        echo "$ALLOCS"
        
        # Save allocation IDs for later use
        nomad job status -json $JOB_NAME | \
          jq -r '.Allocations[].ID' > /tmp/helen-allocations.txt
        
        # Get the primary allocation for logs
        PRIMARY_ALLOC=$(nomad job status -json $JOB_NAME | \
          jq -r '.Allocations[0].ID')
        echo "$PRIMARY_ALLOC" > /tmp/helen-primary-allocation.txt
    - require:
      - cmd: helen_wait_for_deployment

# Set up log streaming (optional)
{% if salt['pillar.get']('helen:enable_log_streaming', false) %}
helen_setup_log_streaming:
  cmd.run:
    - name: |
        ALLOC_ID=$(cat /tmp/helen-primary-allocation.txt)
        LOG_DIR="/var/log/helen/{{ environment }}"
        mkdir -p "$LOG_DIR"
        
        # Create systemd service for log streaming
        cat > /etc/systemd/system/helen-logs-{{ environment }}.service <<EOF
        [Unit]
        Description=Helen {{ mode }} {{ environment }} log streaming
        After=network.target
        
        [Service]
        Type=simple
        ExecStart=/usr/local/bin/nomad alloc logs -f $ALLOC_ID
        StandardOutput=append:${LOG_DIR}/helen.log
        StandardError=append:${LOG_DIR}/helen-error.log
        Restart=always
        RestartSec=10
        
        [Install]
        WantedBy=multi-user.target
        EOF
        
        systemctl daemon-reload
        systemctl enable helen-logs-{{ environment }}
        systemctl start helen-logs-{{ environment }}
    - require:
      - cmd: helen_get_allocation_info
{% endif %}

# Create deployment record in Consul KV
helen_record_deployment:
  consul.put:
    - name: helen/deployments/{{ environment }}/latest
    - value: |
        {
          "job_name": "helen-{{ mode }}-{{ environment }}",
          "mode": "{{ mode }}",
          "environment": "{{ environment }}",
          "deployed_at": "{{ salt['cmd.run']('date -u +%Y-%m-%dT%H:%M:%SZ') }}",
          "deployed_by": "{{ salt['environ.get']('USER', 'eos') }}",
          "version": "{{ salt['pillar.get']('helen:git_commit', 'latest') }}",
          "docker_image": "{{ salt['pillar.get']('helen:docker_image') }}",
          "instance_count": {{ salt['pillar.get']('helen:instance_count', 1) }},
          "allocations": {{ salt['cmd.run']('cat /tmp/helen-allocations.txt | jq -R . | jq -s .', python_shell=True) }}
        }
    - require:
      - cmd: helen_get_allocation_info

# Clean up temporary files
helen_cleanup_temp_files:
  file.absent:
    - names:
      - /tmp/helen-current-count
      - /tmp/helen-deployment-plan.txt
      - /tmp/helen-allocations.txt
      - /tmp/helen-primary-allocation.txt
    - require:
      - consul: helen_record_deployment