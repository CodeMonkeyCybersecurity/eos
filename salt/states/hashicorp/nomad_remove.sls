# Nomad Removal State
# Handles graceful removal of Nomad with options to preserve data

{% set ensure = salt['pillar.get']('nomad:ensure', 'absent') %}
{% set force = salt['pillar.get']('nomad:force', False) %}
{% set keep_data = salt['pillar.get']('nomad:keep_data', False) %}
{% set keep_config = salt['pillar.get']('nomad:keep_config', False) %}
{% set keep_user = salt['pillar.get']('nomad:keep_user', False) %}
{% set timeout = salt['pillar.get']('nomad:timeout', 300) %}
{% set server_mode = salt['pillar.get']('nomad:server_mode', False) %}
{% set client_mode = salt['pillar.get']('nomad:client_mode', False) %}
{% set node_id = salt['pillar.get']('nomad:node_id', '') %}

{% if ensure == 'absent' %}

# Pre-removal tasks
nomad_pre_removal_checks:
  cmd.run:
    - name: |
        set -e
        echo "Starting Nomad removal process..."
        
        # Check if Nomad is installed
        if ! command -v nomad >/dev/null 2>&1; then
          echo "Nomad is not installed"
          exit 0
        fi
        
        # Check if service is running
        if systemctl is-active --quiet nomad; then
          echo "Nomad service is currently running"
          NOMAD_RUNNING=true
        else
          echo "Nomad service is not running"
          NOMAD_RUNNING=false
        fi
        
        # Export for other states
        echo "NOMAD_RUNNING=$NOMAD_RUNNING" > /tmp/nomad_removal_state
    - shell: /bin/bash

# Graceful node draining (if not forced)
{% if not force %}
nomad_drain_node:
  cmd.run:
    - name: |
        set -e
        source /tmp/nomad_removal_state || true
        
        if [ "$NOMAD_RUNNING" = "true" ] && command -v nomad >/dev/null 2>&1; then
          echo "Checking node status..."
          
          # Get node ID if not provided
          if [ -z "{{ node_id }}" ]; then
            NODE_ID=$(nomad node status -self -short 2>/dev/null | grep -E '^[a-f0-9]{8}' | head -1 | awk '{print $1}' || true)
          else
            NODE_ID="{{ node_id }}"
          fi
          
          if [ -n "$NODE_ID" ]; then
            echo "Draining node: $NODE_ID"
            nomad node drain -enable -yes -deadline {{ timeout }}s "$NODE_ID" || {
              echo "Warning: Failed to drain node, continuing anyway"
            }
            
            # Wait for drain to complete
            echo "Waiting for node drain to complete..."
            WAIT_TIME=0
            while [ $WAIT_TIME -lt {{ timeout }} ]; do
              if nomad node status "$NODE_ID" 2>/dev/null | grep -q "ineligible"; then
                echo "Node successfully drained"
                break
              fi
              sleep 5
              WAIT_TIME=$((WAIT_TIME + 5))
            done
          fi
        fi
    - shell: /bin/bash
    - require:
      - cmd: nomad_pre_removal_checks
    - timeout: {{ timeout + 60 }}

# Stop running jobs (if server mode)
{% if server_mode %}
nomad_stop_jobs:
  cmd.run:
    - name: |
        set -e
        source /tmp/nomad_removal_state || true
        
        if [ "$NOMAD_RUNNING" = "true" ] && command -v nomad >/dev/null 2>&1; then
          echo "Stopping all running jobs..."
          
          # Get list of running jobs
          JOBS=$(nomad job status -short 2>/dev/null | grep -E '^[a-zA-Z0-9_-]+\s+running' | awk '{print $1}' || true)
          
          if [ -n "$JOBS" ]; then
            for job in $JOBS; do
              echo "Stopping job: $job"
              nomad job stop -yes "$job" || echo "Warning: Failed to stop job $job"
            done
            
            # Wait for jobs to stop
            echo "Waiting for jobs to stop..."
            sleep 10
          else
            echo "No running jobs found"
          fi
        fi
    - shell: /bin/bash
    - require:
      - cmd: nomad_drain_node
    - timeout: {{ timeout }}
{% endif %}
{% endif %}

# Stop Nomad service
nomad_stop_service:
  service.dead:
    - name: nomad
    - enable: False
    {% if not force %}
    - require:
      {% if server_mode %}
      - cmd: nomad_stop_jobs
      {% else %}
      - cmd: nomad_drain_node
      {% endif %}
    {% endif %}

# Wait for service to fully stop
nomad_wait_for_stop:
  cmd.run:
    - name: |
        echo "Waiting for Nomad to fully stop..."
        WAIT_TIME=0
        while [ $WAIT_TIME -lt 30 ]; do
          if ! pgrep -x nomad >/dev/null; then
            echo "Nomad process has stopped"
            break
          fi
          sleep 2
          WAIT_TIME=$((WAIT_TIME + 2))
        done
        
        # Force kill if still running and force mode
        {% if force %}
        if pgrep -x nomad >/dev/null; then
          echo "Force killing Nomad process..."
          pkill -9 nomad || true
          sleep 2
        fi
        {% endif %}
    - shell: /bin/bash
    - require:
      - service: nomad_stop_service

# Remove Nomad package
nomad_remove_package:
  pkg.removed:
    - name: nomad
    - require:
      - cmd: nomad_wait_for_stop

# Remove Nomad binary if installed manually
nomad_remove_binary:
  file.absent:
    - name: /usr/local/bin/nomad
    - require:
      - pkg: nomad_remove_package

# Remove data directories
{% if not keep_data %}
nomad_remove_data:
  file.absent:
    - names:
      - /opt/nomad
      - /var/lib/nomad
      - /var/nomad
    - require:
      - pkg: nomad_remove_package
{% else %}
nomad_preserve_data:
  cmd.run:
    - name: echo "Preserving Nomad data directories as requested"
{% endif %}

# Remove configuration
{% if not keep_config %}
nomad_remove_config:
  file.absent:
    - names:
      - /etc/nomad.d
      - /etc/nomad
      - /etc/nomad.hcl
    - require:
      - pkg: nomad_remove_package
{% else %}
nomad_preserve_config:
  cmd.run:
    - name: echo "Preserving Nomad configuration as requested"
{% endif %}

# Remove systemd service file
nomad_remove_service_file:
  file.absent:
    - name: /etc/systemd/system/nomad.service
    - require:
      - service: nomad_stop_service

# Reload systemd
nomad_reload_systemd:
  cmd.run:
    - name: systemctl daemon-reload
    - require:
      - file: nomad_remove_service_file

# Remove Nomad user and group
{% if not keep_user %}
nomad_remove_user:
  user.absent:
    - name: nomad
    - purge: True
    - require:
      - pkg: nomad_remove_package

nomad_remove_group:
  group.absent:
    - name: nomad
    - require:
      - user: nomad_remove_user
{% else %}
nomad_preserve_user:
  cmd.run:
    - name: echo "Preserving Nomad user and group as requested"
{% endif %}

# Clean up temporary files
nomad_cleanup_temp:
  file.absent:
    - names:
      - /tmp/nomad_removal_state
      - /tmp/nomad-*
      - /var/tmp/nomad-*

# Remove from Consul if integrated
nomad_deregister_consul:
  cmd.run:
    - name: |
        if command -v consul >/dev/null 2>&1 && consul members >/dev/null 2>&1; then
          echo "Deregistering Nomad services from Consul..."
          # Deregister common Nomad services
          for service in nomad nomad-client nomad-server; do
            consul services deregister "$service" 2>/dev/null || true
          done
        fi
    - shell: /bin/bash
    - require:
      - service: nomad_stop_service

# Final verification
nomad_verify_removal:
  cmd.run:
    - name: |
        echo "Verifying Nomad removal..."
        
        # Check if binary exists
        if command -v nomad >/dev/null 2>&1; then
          echo "WARNING: Nomad binary still exists at $(which nomad)"
        else
          echo "✓ Nomad binary removed"
        fi
        
        # Check if service exists
        if systemctl list-unit-files | grep -q nomad.service; then
          echo "WARNING: Nomad service file still exists"
        else
          echo "✓ Nomad service removed"
        fi
        
        # Check processes
        if pgrep -x nomad >/dev/null; then
          echo "WARNING: Nomad process is still running"
        else
          echo "✓ No Nomad processes running"
        fi
        
        # Summary
        echo ""
        echo "Nomad removal completed with options:"
        echo "- Force removal: {{ force }}"
        echo "- Data preserved: {{ keep_data }}"
        echo "- Config preserved: {{ keep_config }}"
        echo "- User preserved: {{ keep_user }}"
    - shell: /bin/bash
    - require:
      - cmd: nomad_cleanup_temp

{% endif %}