#!/bin/bash
# recover-hashicorp.sh
# Recovery script for HashiCorp stack services (Consul, Vault, Nomad)
# This script fixes common issues with disabled or broken HashiCorp services

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Service status tracking
declare -A SERVICE_STATUS
RECOVERY_LOG="/var/log/eos-hashicorp-recovery.log"

# Initialize logging
log() {
    echo -e "${1}" | tee -a "$RECOVERY_LOG"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$RECOVERY_LOG"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$RECOVERY_LOG"
}

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$RECOVERY_LOG"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$RECOVERY_LOG"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Fix /etc/eos/ permissions
fix_eos_permissions() {
    log_info "Fixing /etc/eos/ directory permissions..."

    if [[ ! -d /etc/eos ]]; then
        mkdir -p /etc/eos
        log_info "Created /etc/eos/ directory"
    fi

    chown -R root:root /etc/eos
    chmod 755 /etc/eos

    # Create necessary subdirectories
    for dir in consul vault nomad bootstrap; do
        if [[ ! -d /etc/eos/$dir ]]; then
            mkdir -p /etc/eos/$dir
            chmod 755 /etc/eos/$dir
            log_info "Created /etc/eos/$dir directory"
        fi
    done

    log_success "Fixed /etc/eos/ permissions"
}

# Check if a port is listening
check_port() {
    local port=$1
    local service=$2

    if ss -tlnp | grep -q ":$port "; then
        log_success "$service is listening on port $port"
        return 0
    else
        log_warn "$service is NOT listening on port $port"
        return 1
    fi
}

# Enable and start a systemd service
enable_and_start_service() {
    local service=$1

    log_info "Enabling and starting $service..."

    # Check if unit file exists
    if ! systemctl list-unit-files | grep -q "^$service.service"; then
        log_error "$service.service unit file not found!"
        return 1
    fi

    # Enable the service
    if systemctl enable $service 2>/dev/null; then
        log_info "$service enabled"
    else
        log_warn "Failed to enable $service (may already be enabled)"
    fi

    # Start the service
    if systemctl start $service 2>/dev/null; then
        log_success "$service started"
    else
        log_error "Failed to start $service"
        # Show status for debugging
        systemctl status $service --no-pager || true
        return 1
    fi

    # Wait for service to stabilize
    sleep 2

    # Check if service is active
    if systemctl is-active $service >/dev/null 2>&1; then
        log_success "$service is active"
        SERVICE_STATUS[$service]="active"
        return 0
    else
        log_error "$service failed to start properly"
        SERVICE_STATUS[$service]="failed"
        return 1
    fi
}

# Check and fix Consul
fix_consul() {
    log_info "\n=== Checking Consul Service ==="

    # Check if Consul binary exists
    if ! command -v consul &> /dev/null; then
        log_error "Consul binary not found in PATH"
        log_info "Please install Consul first: eos create consul"
        return 1
    fi

    # Enable and start Consul
    if enable_and_start_service "consul"; then
        # Check standard Consul ports
        check_port 8500 "Consul HTTP API"
        check_port 8300 "Consul Server RPC"
        check_port 8301 "Consul Serf LAN"
        check_port 8302 "Consul Serf WAN"
        check_port 8600 "Consul DNS"

        # Also check Eos custom ports
        check_port 8161 "Consul (EOS custom)"

        # Test Consul API
        if curl -s http://localhost:8500/v1/status/leader >/dev/null 2>&1; then
            log_success "Consul API is responding"

            # Get Consul version
            CONSUL_VERSION=$(consul version | head -1 | awk '{print $2}')
            log_info "Consul version: $CONSUL_VERSION"
        else
            log_warn "Consul API not responding yet"
        fi
    else
        log_error "Failed to recover Consul service"
        return 1
    fi
}

# Check and fix Vault
fix_vault() {
    log_info "\n=== Checking Vault Service ==="

    # Check if Vault binary exists
    if ! command -v vault &> /dev/null; then
        log_error "Vault binary not found in PATH"
        log_info "Please install Vault first: eos create vault"
        return 1
    fi

    # Enable and start Vault
    if enable_and_start_service "vault"; then
        # Check standard Vault port
        check_port 8200 "Vault HTTP API"

        # Also check Eos custom port
        check_port 8179 "Vault (EOS custom HTTPS)"

        # Export VAULT_ADDR for CLI commands
        export VAULT_ADDR="http://localhost:8200"

        # Check Vault status
        if vault status >/dev/null 2>&1; then
            VAULT_STATUS=$(vault status -format=json 2>/dev/null || echo "{}")

            # Check if initialized
            if echo "$VAULT_STATUS" | jq -e '.initialized == false' >/dev/null 2>&1; then
                log_warn "Vault is NOT initialized"
                log_info "To initialize Vault, run: vault operator init"
                log_info "Save the unseal keys and root token securely!"
            elif echo "$VAULT_STATUS" | jq -e '.sealed == true' >/dev/null 2>&1; then
                log_warn "Vault is SEALED"
                log_info "To unseal Vault, run: vault operator unseal <unseal-key>"
                log_info "You need to provide 3 unseal keys (by default)"
            else
                log_success "Vault is initialized and unsealed"

                # Get Vault version
                VAULT_VERSION=$(vault version | awk '{print $2}')
                log_info "Vault version: $VAULT_VERSION"
            fi
        else
            log_error "Cannot connect to Vault API"
            log_info "Check logs: journalctl -u vault -n 50"
        fi
    else
        log_error "Failed to recover Vault service"
        return 1
    fi
}

# Check and fix Nomad
fix_nomad() {
    log_info "\n=== Checking Nomad Service ==="

    # Check if Nomad binary exists
    if ! command -v nomad &> /dev/null; then
        log_warn "Nomad binary not found in PATH"
        log_info "Nomad is optional. To install: eos create nomad"
        return 0  # Not a failure since Nomad is optional
    fi

    # Enable and start Nomad
    if enable_and_start_service "nomad"; then
        # Check standard Nomad ports
        check_port 4646 "Nomad HTTP API"
        check_port 4647 "Nomad RPC"
        check_port 4648 "Nomad Serf"

        # Also check Eos custom ports
        check_port 8243 "Nomad (EOS custom)"

        # Test Nomad API
        if curl -s http://localhost:4646/v1/status/leader >/dev/null 2>&1; then
            log_success "Nomad API is responding"

            # Get Nomad version
            NOMAD_VERSION=$(nomad version | head -1 | awk '{print $2}')
            log_info "Nomad version: $NOMAD_VERSION"
        else
            log_warn "Nomad API not responding yet"
        fi
    else
        log_warn "Failed to recover Nomad service (optional)"
    fi
}

# Create systemd service files if missing
create_missing_service_files() {
    log_info "\n=== Checking for missing service files ==="

    # Consul service file
    if [[ ! -f /etc/systemd/system/consul.service ]]; then
        log_info "Creating Consul service file..."
        cat > /etc/systemd/system/consul.service <<EOF
[Unit]
Description=HashiCorp Consul
Documentation=https://www.consul.io/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/consul/consul.hcl

[Service]
Type=notify
User=consul
Group=consul
ExecStart=/usr/local/bin/consul agent -config-dir=/etc/consul
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        log_success "Created Consul service file"
    fi

    # Vault service file
    if [[ ! -f /etc/systemd/system/vault.service ]]; then
        log_info "Creating Vault service file..."
        cat > /etc/systemd/system/vault.service <<EOF
[Unit]
Description=HashiCorp Vault
Documentation=https://www.vaultproject.io/docs/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/vault/vault.hcl
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=notify
EnvironmentFile=/etc/vault/vault.env
User=vault
Group=vault
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
SecureBits=keep-caps
AmbientCapabilities=CAP_IPC_LOCK
Capabilities=CAP_IPC_LOCK+ep
CapabilityBoundingSet=CAP_SYSLOG CAP_IPC_LOCK
NoNewPrivileges=yes
ExecStart=/usr/local/bin/vault server -config=/etc/vault
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        log_success "Created Vault service file"
    fi
}

# Generate summary report
generate_report() {
    log_info "\n========================================="
    log_info "     HashiCorp Services Recovery Report"
    log_info "========================================="

    echo ""
    echo -e "${BLUE}Service Status:${NC}"
    echo "----------------------------------------"

    for service in consul vault nomad; do
        if systemctl is-active $service >/dev/null 2>&1; then
            echo -e "$service: ${GREEN}● ACTIVE${NC}"
        elif systemctl is-enabled $service >/dev/null 2>&1; then
            echo -e "$service: ${YELLOW}○ ENABLED (not running)${NC}"
        else
            echo -e "$service: ${RED}○ DISABLED${NC}"
        fi
    done

    echo ""
    echo -e "${BLUE}Port Status:${NC}"
    echo "----------------------------------------"

    # Check all HashiCorp ports
    declare -A PORTS=(
        ["8179"]="Vault HTTPS (EOS)"
        ["8200"]="Vault HTTP"
        ["8161"]="Consul (EOS)"
        ["8500"]="Consul HTTP"
        ["8300"]="Consul Server"
        ["8301"]="Consul LAN"
        ["8302"]="Consul WAN"
        ["8600"]="Consul DNS"
        ["8243"]="Nomad (EOS)"
        ["4646"]="Nomad HTTP"
        ["4647"]="Nomad RPC"
        ["4648"]="Nomad Serf"
    )

    for port in "${!PORTS[@]}"; do
        if ss -tlnp 2>/dev/null | grep -q ":$port "; then
            echo -e "Port $port (${PORTS[$port]}): ${GREEN}LISTENING${NC}"
        else
            echo -e "Port $port (${PORTS[$port]}): ${RED}CLOSED${NC}"
        fi
    done | sort -n

    echo ""
    echo -e "${BLUE}Next Steps:${NC}"
    echo "----------------------------------------"

    # Vault initialization check
    if command -v vault &> /dev/null; then
        export VAULT_ADDR="http://localhost:8200"
        if vault status 2>/dev/null | grep -q "Initialized.*false"; then
            echo "1. Initialize Vault:"
            echo "   vault operator init"
            echo ""
        elif vault status 2>/dev/null | grep -q "Sealed.*true"; then
            echo "1. Unseal Vault:"
            echo "   vault operator unseal <key1>"
            echo "   vault operator unseal <key2>"
            echo "   vault operator unseal <key3>"
            echo ""
        fi
    fi

    echo "2. Verify services:"
    echo "   systemctl status consul vault nomad"
    echo ""
    echo "3. Check logs if issues persist:"
    echo "   journalctl -u consul -n 50"
    echo "   journalctl -u vault -n 50"
    echo "   journalctl -u nomad -n 50"
    echo ""
    echo "4. Re-run bootstrap if needed:"
    echo "   sudo eos bootstrap --force"
    echo ""

    log_info "Recovery log saved to: $RECOVERY_LOG"
}

# Main execution
main() {
    echo "========================================="
    echo "   HashiCorp Services Recovery Script"
    echo "========================================="
    echo ""

    # Start logging
    echo "[$(date)] Starting HashiCorp recovery" > "$RECOVERY_LOG"

    check_root
    fix_eos_permissions
    create_missing_service_files

    # Fix services
    fix_consul
    fix_vault
    fix_nomad

    # Generate final report
    generate_report

    log_success "\nRecovery process completed!"
}

# Run main function
main "$@"