# Start and enable Nomad service

# Enable and start Nomad service
nomad_service:
  service.running:
    - name: nomad
    - enable: True
    - require:
      - pkg: install_nomad
      - file: nomad_config
      - file: nomad_env_file
      - cmd: systemd_reload
    - watch:
      - file: nomad_config
      - file: nomad_env_file

# Wait for Nomad to be ready
wait_for_nomad:
  cmd.run:
    - name: |
        for i in {1..30}; do
          if nomad status >/dev/null 2>&1; then
            echo "Nomad is ready"
            exit 0
          fi
          echo "Waiting for Nomad to be ready... ($i/30)"
          sleep 2
        done
        echo "Nomad failed to become ready"
        exit 1
    - require:
      - service: nomad_service

# Create firewall rules for Nomad ports
nomad_firewall_http:
  cmd.run:
    - name: ufw allow {{ pillar.get('nomad', {}).get('http_port', 4646) }}/tcp
    - onlyif: which ufw

nomad_firewall_rpc:
  cmd.run:
    - name: ufw allow {{ pillar.get('nomad', {}).get('rpc_port', 4647) }}/tcp
    - onlyif: which ufw

nomad_firewall_serf:
  cmd.run:
    - name: ufw allow {{ pillar.get('nomad', {}).get('serf_port', 4648) }}/tcp
    - onlyif: which ufw

# Create basic health check script
nomad_health_check:
  file.managed:
    - name: /usr/local/bin/nomad-health-check
    - mode: 755
    - contents: |
        #!/bin/bash
        # Nomad health check script
        
        # Check if Nomad service is running
        if ! systemctl is-active --quiet nomad; then
          echo "ERROR: Nomad service is not running"
          exit 1
        fi
        
        # Check if Nomad API is responding
        if ! nomad status >/dev/null 2>&1; then
          echo "ERROR: Nomad API is not responding"
          exit 1
        fi
        
        # Check if this is a server node
        if nomad server members >/dev/null 2>&1; then
          echo "✓ Nomad server is healthy"
        fi
        
        # Check if this is a client node
        if nomad node status >/dev/null 2>&1; then
          echo "✓ Nomad client is healthy"
        fi
        
        echo "✓ Nomad cluster is healthy"
        exit 0

# Create cron job for health monitoring
nomad_health_cron:
  cron.present:
    - name: /usr/local/bin/nomad-health-check
    - user: root
    - minute: '*/5'
    - comment: 'Nomad health check'
    - require:
      - file: nomad_health_check