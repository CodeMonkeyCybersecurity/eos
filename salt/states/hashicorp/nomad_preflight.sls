# Nomad Pre-flight Checks
# Comprehensive idempotent checks before Nomad installation

{% set force = salt['pillar.get']('nomad:force', False) %}
{% set clean = salt['pillar.get']('nomad:clean', False) %}
{% set server_mode = salt['pillar.get']('nomad:server_mode', False) %}
{% set client_mode = salt['pillar.get']('nomad:client_mode', True) %}

# Check system requirements
nomad_check_system:
  cmd.run:
    - name: |
        echo "=== Nomad Pre-flight Checks ==="
        echo "Date: $(date)"
        echo "Hostname: $(hostname)"
        echo "Force mode: {{ force }}"
        echo "Clean mode: {{ clean }}"
        echo ""
        
        # Check OS
        if ! grep -q "Ubuntu" /etc/os-release; then
          echo "ERROR: This installation requires Ubuntu"
          exit 1
        fi
        echo "✓ Operating System: Ubuntu $(lsb_release -rs)"
        
        # Check architecture
        ARCH=$(uname -m)
        if [ "$ARCH" != "x86_64" ] && [ "$ARCH" != "aarch64" ]; then
          echo "ERROR: Unsupported architecture: $ARCH"
          exit 1
        fi
        echo "✓ Architecture: $ARCH"
        
        # Check minimum requirements
        MEM_TOTAL=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        MEM_GB=$((MEM_TOTAL / 1024 / 1024))
        if [ $MEM_GB -lt 1 ]; then
          echo "WARNING: Less than 1GB RAM detected ($MEM_GB GB)"
        else
          echo "✓ Memory: $MEM_GB GB"
        fi
        
        # Check disk space
        DISK_AVAIL=$(df /var/lib | tail -1 | awk '{print $4}')
        DISK_GB=$((DISK_AVAIL / 1024 / 1024))
        if [ $DISK_GB -lt 5 ]; then
          echo "WARNING: Less than 5GB disk space available ($DISK_GB GB)"
        else
          echo "✓ Disk space: $DISK_GB GB available"
        fi
    - stateful: False
    - unless: {{ force }}

# Check for existing Nomad installation
nomad_check_existing:
  cmd.run:
    - name: |
        echo ""
        echo "=== Checking Existing Installation ==="
        
        NOMAD_EXISTS=false
        NOMAD_RUNNING=false
        NOMAD_VERSION=""
        
        # Check if binary exists
        if command -v nomad >/dev/null 2>&1; then
          NOMAD_EXISTS=true
          NOMAD_VERSION=$(nomad version | head -n1 || echo "unknown")
          echo "Found Nomad binary: $NOMAD_VERSION"
          
          # Check if service is running
          if systemctl is-active nomad.service >/dev/null 2>&1; then
            NOMAD_RUNNING=true
            echo "Nomad service is running"
            
            # Get agent info if running
            if nomad agent-info >/dev/null 2>&1; then
              echo ""
              echo "Agent Information:"
              nomad agent-info 2>/dev/null | grep -E "(server|client|version)" || true
            fi
            
            # Check for running jobs
            JOB_COUNT=$(nomad job status -short 2>/dev/null | grep -v "^ID" | wc -l || echo "0")
            if [ "$JOB_COUNT" -gt 0 ]; then
              echo ""
              echo "WARNING: $JOB_COUNT Nomad jobs are currently running"
              nomad job status -short 2>/dev/null || true
            fi
          fi
        fi
        
        # Decide action based on flags
        {% if not force and not clean %}
        if [ "$NOMAD_EXISTS" = "true" ] && [ "$NOMAD_RUNNING" = "true" ]; then
          echo ""
          echo "ERROR: Nomad is already installed and running"
          echo "Use --force to reconfigure or --clean for clean install"
          exit 1
        fi
        {% endif %}
        
        {% if clean %}
        if [ "$NOMAD_EXISTS" = "true" ]; then
          echo ""
          echo "Clean mode enabled - will remove existing installation"
        fi
        {% endif %}
    - stateful: False

# Check port availability
nomad_check_ports:
  cmd.run:
    - name: |
        echo ""
        echo "=== Checking Port Availability ==="
        
        check_port() {
          local port=$1
          local service=$2
          if lsof -i:$port >/dev/null 2>&1; then
            echo "ERROR: Port $port ($service) is already in use:"
            lsof -i:$port | grep LISTEN || true
            return 1
          else
            echo "✓ Port $port ($service) is available"
            return 0
          fi
        }
        
        ALL_CLEAR=true
        
        # HTTP API port
        check_port 4646 "HTTP API" || ALL_CLEAR=false
        
        # RPC port  
        check_port 4647 "RPC" || ALL_CLEAR=false
        
        # Serf WAN port (servers only)
        {% if server_mode %}
        check_port 4648 "Serf WAN" || ALL_CLEAR=false
        {% endif %}
        
        {% if force %}
        if [ "$ALL_CLEAR" = "false" ]; then
          echo ""
          echo "WARNING: Some ports are in use, but --force specified"
          echo "Will attempt to stop conflicting services"
        fi
        {% else %}
        if [ "$ALL_CLEAR" = "false" ]; then
          echo ""
          echo "ERROR: Required ports are not available"
          echo "Stop conflicting services or use --force"
          exit 1
        fi
        {% endif %}
    - require:
      - cmd: nomad_check_system
    - unless: {{ force }}

# Check Docker availability (for client nodes)
{% if client_mode and salt['pillar.get']('nomad:enable_docker', True) %}
nomad_check_docker:
  cmd.run:
    - name: |
        echo ""
        echo "=== Checking Docker Installation ==="
        
        if command -v docker >/dev/null 2>&1; then
          if docker info >/dev/null 2>&1; then
            echo "✓ Docker is installed and running"
            echo "  Version: $(docker --version)"
          else
            echo "WARNING: Docker is installed but not accessible"
            echo "Nomad client will have limited functionality"
          fi
        else
          echo "WARNING: Docker is not installed"
          echo "Install Docker for container workloads: eos create docker"
        fi
    - require:
      - cmd: nomad_check_ports
{% endif %}

# Check Consul integration
nomad_check_consul:
  cmd.run:
    - name: |
        echo ""
        echo "=== Checking Consul Integration ==="
        
        if systemctl is-active consul.service >/dev/null 2>&1; then
          echo "✓ Consul is running - will enable integration"
          
          # Check Consul health
          if consul members >/dev/null 2>&1; then
            echo "  Consul cluster members:"
            consul members 2>/dev/null | head -5 || true
          fi
        else
          echo "⚠ Consul is not running"
          echo "  Nomad will operate without service discovery"
          echo "  Install Consul: eos create consul"
        fi
    - require:
      - cmd: nomad_check_ports

# Check Vault integration  
nomad_check_vault:
  cmd.run:
    - name: |
        echo ""
        echo "=== Checking Vault Integration ==="
        
        if systemctl is-active vault.service >/dev/null 2>&1; then
          echo "✓ Vault is running - will enable integration"
          
          # Check Vault status
          if vault status >/dev/null 2>&1; then
            echo "  Vault is unsealed and ready"
          else
            echo "  WARNING: Vault may be sealed"
          fi
        else
          echo "⚠ Vault is not running"
          echo "  Nomad will operate without secrets management"
          echo "  Install Vault: eos create vault"
        fi
    - require:
      - cmd: nomad_check_consul

# Check network configuration
nomad_check_network:
  cmd.run:
    - name: |
        echo ""
        echo "=== Checking Network Configuration ==="
        
        # Get primary network interface
        PRIMARY_IFACE=$(ip route | grep default | head -1 | awk '{print $5}')
        if [ -z "$PRIMARY_IFACE" ]; then
          echo "ERROR: No default network interface found"
          exit 1
        fi
        echo "✓ Primary interface: $PRIMARY_IFACE"
        
        # Get IP address
        PRIMARY_IP=$(ip -4 addr show $PRIMARY_IFACE | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
        if [ -z "$PRIMARY_IP" ]; then
          echo "ERROR: No IPv4 address found on $PRIMARY_IFACE"
          exit 1
        fi
        echo "✓ Primary IP: $PRIMARY_IP"
        
        # Check if we can bind to advertise address
        ADVERTISE_ADDR="{{ salt['pillar.get']('nomad:advertise_addr', '') }}"
        if [ -n "$ADVERTISE_ADDR" ] && [ "$ADVERTISE_ADDR" != "$PRIMARY_IP" ]; then
          echo "  Custom advertise address: $ADVERTISE_ADDR"
          # TODO: Validate custom advertise address
        fi
        
        # Store network info for later use
        echo "PRIMARY_IFACE=$PRIMARY_IFACE" > /tmp/nomad_network_info
        echo "PRIMARY_IP=$PRIMARY_IP" >> /tmp/nomad_network_info
    - require:
      - cmd: nomad_check_vault

# Summary and confirmation
nomad_preflight_summary:
  cmd.run:
    - name: |
        echo ""
        echo "=== Pre-flight Check Summary ==="
        echo "Installation mode: {% if server_mode %}SERVER{% else %}CLIENT{% endif %}"
        echo "Datacenter: {{ salt['pillar.get']('nomad:datacenter', 'dc1') }}"
        echo "Region: {{ salt['pillar.get']('nomad:region', 'global') }}"
        
        {% if server_mode %}
        echo "Bootstrap expect: {{ salt['pillar.get']('nomad:bootstrap_expect', 1) }}"
        {% endif %}
        
        {% if client_mode %}
        echo "Enable Docker: {{ salt['pillar.get']('nomad:enable_docker', True) }}"
        echo "Enable raw_exec: {{ salt['pillar.get']('nomad:enable_raw_exec', False) }}"
        {% endif %}
        
        echo ""
        echo "All pre-flight checks completed successfully"
        echo "Ready to install Nomad"
    - require:
      - cmd: nomad_check_network