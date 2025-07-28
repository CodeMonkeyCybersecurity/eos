#!/bin/bash
# Debug script to trace service detection and mapping in bootstrap

set -e

echo "=== Bootstrap Service Detection Debug Script ==="
echo "This script helps debug where process paths are being used instead of service names"
echo

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to check what's using a port
check_port() {
    local port=$1
    echo -e "${BLUE}Checking port $port:${NC}"
    
    # Using ss command (same as bootstrap)
    echo "  ss output:"
    ss -tlnp 2>/dev/null | grep ":$port " || echo "    Port not in use"
    
    # Using lsof as alternative
    echo "  lsof output:"
    sudo lsof -i :$port 2>/dev/null | grep LISTEN || echo "    Port not in use"
    
    # Check systemctl status by PID if found
    local pid=$(ss -tlnp 2>/dev/null | grep ":$port " | grep -oP 'pid=\K\d+' | head -1)
    if [ -n "$pid" ]; then
        echo "  Process info (PID $pid):"
        ps -p $pid -o comm,cmd --no-headers 2>/dev/null || echo "    Process not found"
        
        echo "  Systemd service:"
        systemctl status $pid 2>&1 | head -n 3 | grep -E '●|Loaded:' || echo "    Not a systemd service"
    fi
    echo
}

# Function to trace service mapping
trace_service_mapping() {
    local process_path=$1
    echo -e "${BLUE}Tracing service mapping for: $process_path${NC}"
    
    # Direct mappings
    case "$process_path" in
        "salt-master") echo "  -> Direct match: salt-master" ;;
        "vault") echo "  -> Direct match: vault" ;;
        "consul") echo "  -> Direct match: consul" ;;
        "nomad") echo "  -> Direct match: nomad" ;;
        "/opt/saltstack/"*) echo "  -> Path match: salt-master" ;;
        "/opt/vault/"*) echo "  -> Path match: vault" ;;
        "/opt/consul/"*) echo "  -> Path match: consul" ;;
        "/opt/nomad/"*) echo "  -> Path match: nomad" ;;
        *) echo "  -> No direct mapping found" ;;
    esac
    
    # Extract executable name
    local exe_name=$(basename "$process_path" 2>/dev/null)
    if [ -n "$exe_name" ] && [ "$exe_name" != "$process_path" ]; then
        echo "  -> Extracted executable: $exe_name"
    fi
}

echo "1. Checking ports used by EOS services..."
echo "=========================================="

# Check all EOS-related ports
ports=(4505 4506 8000 8200 8300 8301 8302 8500 8600 4646 4647 4648)
for port in "${ports[@]}"; do
    if ss -tlnp 2>/dev/null | grep -q ":$port "; then
        check_port $port
    fi
done

echo "2. Testing service name mappings..."
echo "==================================="

# Test various process paths that might be encountered
test_paths=(
    "/opt/saltstack/"
    "/opt/saltstack"
    "salt-master"
    "/usr/bin/salt-master"
    "/opt/vault/bin/vault"
    "vault"
    "/usr/bin/vault"
    "python3"
    "/usr/bin/python3"
)

for path in "${test_paths[@]}"; do
    trace_service_mapping "$path"
done

echo
echo "3. Current service status..."
echo "============================"

# Check status of EOS services
services=("salt-master" "salt-api" "vault" "consul" "nomad")
for service in "${services[@]}"; do
    echo -n "$service: "
    if systemctl is-active --quiet $service 2>/dev/null; then
        echo -e "${GREEN}active${NC}"
        # Get the main PID
        pid=$(systemctl show -p MainPID --value $service 2>/dev/null)
        if [ -n "$pid" ] && [ "$pid" != "0" ]; then
            echo "  PID: $pid"
            echo -n "  Process: "
            ps -p $pid -o comm= 2>/dev/null || echo "unknown"
        fi
    else
        echo -e "${RED}inactive${NC}"
    fi
done

echo
echo "4. Debugging bootstrap detection..."
echo "==================================="

# Set debug environment variable
export EOS_LOG_LEVEL=debug

echo "To see detailed debug output during bootstrap, run:"
echo -e "${YELLOW}  EOS_LOG_LEVEL=debug sudo eos bootstrap --dry-run${NC}"
echo
echo "To test service stopping without actually stopping:"
echo -e "${YELLOW}  sudo eos bootstrap --dry-run --stop-conflicting${NC}"
echo
echo "To see what the bootstrap would detect:"
echo -e "${YELLOW}  sudo eos bootstrap --verify${NC}"

echo
echo "5. Common issues and solutions..."
echo "================================="

echo -e "${BLUE}Issue:${NC} Service shows as '/opt/saltstack/' instead of 'salt-master'"
echo -e "${GREEN}Solution:${NC} The fix should map this to 'salt-master' automatically"
echo

echo -e "${BLUE}Issue:${NC} systemctl stop fails with 'Unit not found'"
echo -e "${GREEN}Solution:${NC} The service name mapping is incorrect or service has a different name"
echo

echo -e "${BLUE}Issue:${NC} Port shows as in use but no service name detected"
echo -e "${GREEN}Solution:${NC} Process might not be a systemd service, check with 'lsof -i :PORT'"

echo
echo "Debug script completed. Check the output above for any issues."