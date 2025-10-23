#!/bin/bash
# scripts/audit_hardcoded_values.sh
# Comprehensive audit of hardcoded values in Eos codebase
# P0 RULE #11: ZERO HARDCODED VALUES
#
# Usage: ./scripts/audit_hardcoded_values.sh [service]
#   service: vault, consul, nomad, or "all" (default: all)
#
# Output: /tmp/eos_hardcoded_audit_[timestamp].txt

set -euo pipefail

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="/tmp"
SERVICE="${1:-all}"
REPORT_FILE="${OUTPUT_DIR}/eos_hardcoded_audit_${SERVICE}_${TIMESTAMP}.txt"

# Color output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Determine search path
if [ "$SERVICE" = "all" ]; then
    SEARCH_PATH="pkg/"
else
    SEARCH_PATH="pkg/${SERVICE}/"
fi

echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}Eos Hardcoded Values Audit - P0 Rule #11 Enforcement${NC}"
echo -e "${BLUE}============================================================${NC}"
echo "Service: $SERVICE"
echo "Search Path: $SEARCH_PATH"
echo "Report: $REPORT_FILE"
echo ""

# Create report header
cat > "$REPORT_FILE" <<EOF
============================================================
Eos Hardcoded Values Audit Report
============================================================
Date: $(date)
Service: $SERVICE
Search Path: $SEARCH_PATH
P0 Rule: #11 - ZERO HARDCODED VALUES

============================================================
SUMMARY
============================================================

This report identifies hardcoded literal values that violate
P0 Rule #11: Constants - SINGLE SOURCE OF TRUTH

ALL values must be defined as constants in:
- Service-specific: pkg/[service]/constants.go
- Shared: pkg/shared/ports.go, pkg/shared/paths.go

============================================================

EOF

# Counters
TOTAL_VIOLATIONS=0

# Function to search and report
search_pattern() {
    local pattern="$1"
    local description="$2"
    local color="$3"

    echo -e "\n${color}Scanning: $description${NC}"
    echo -e "\n============================================================" >> "$REPORT_FILE"
    echo "$description" >> "$REPORT_FILE"
    echo "============================================================" >> "$REPORT_FILE"

    # Exclude test files, generated files, and docs
    results=$(grep -rn --include="*.go" \
        --exclude="*_test.go" \
        --exclude="*.pb.go" \
        --exclude="*_string.go" \
        "$pattern" "$SEARCH_PATH" 2>/dev/null || true)

    if [ -n "$results" ]; then
        count=$(echo "$results" | wc -l | tr -d ' ')
        echo -e "${RED}  Found $count violations${NC}"
        echo "$results" >> "$REPORT_FILE"
        TOTAL_VIOLATIONS=$((TOTAL_VIOLATIONS + count))
    else
        echo -e "${GREEN}  ✓ No violations found${NC}"
        echo "No violations found" >> "$REPORT_FILE"
    fi
}

#============================================================
# 1. FILE PATHS
#============================================================

echo -e "\n${BLUE}[1/12] FILE PATHS${NC}"

# Absolute paths starting with /
search_pattern '"/usr/' "Paths: /usr/*" "$YELLOW"
search_pattern '"/etc/' "Paths: /etc/*" "$YELLOW"
search_pattern '"/opt/' "Paths: /opt/*" "$YELLOW"
search_pattern '"/var/' "Paths: /var/*" "$YELLOW"
search_pattern '"/run/' "Paths: /run/*" "$YELLOW"
search_pattern '"/tmp/' "Paths: /tmp/*" "$YELLOW"

#============================================================
# 2. IP ADDRESSES
#============================================================

echo -e "\n${BLUE}[2/12] IP ADDRESSES${NC}"

search_pattern '"127\.0\.0\.1"' "IP: shared.GetInternalHostname (localhost)" "$YELLOW"
search_pattern '"0\.0\.0\.0"' "IP: 0.0.0.0 (all interfaces)" "$YELLOW"
search_pattern '"::1"' "IP: ::1 (IPv6 localhost)" "$YELLOW"
search_pattern '"localhost"' "Hostname: localhost" "$YELLOW"

#============================================================
# 3. PORT NUMBERS
#============================================================

echo -e "\n${BLUE}[3/12] PORT NUMBERS${NC}"

# HashiCorp ports
search_pattern ':8200[^0-9]' "Port: 8200 (Vault default)" "$YELLOW"
search_pattern ':8179[^0-9]' "Port: 8179 (Vault Eos)" "$YELLOW"
search_pattern ':8500[^0-9]' "Port: 8500 (Consul)" "$YELLOW"
search_pattern ':4646[^0-9]' "Port: 4646 (Nomad)" "$YELLOW"

# Database ports
search_pattern ':5432[^0-9]' "Port: 5432 (PostgreSQL)" "$YELLOW"
search_pattern ':3306[^0-9]' "Port: 3306 (MySQL)" "$YELLOW"
search_pattern ':6379[^0-9]' "Port: 6379 (Redis)" "$YELLOW"

#============================================================
# 4. SERVICE/USER/GROUP NAMES
#============================================================

echo -e "\n${BLUE}[4/12] SERVICE/USER/GROUP NAMES${NC}"

search_pattern '"vault\.service"' "Service: vault.service" "$YELLOW"
search_pattern '"consul\.service"' "Service: consul.service" "$YELLOW"
search_pattern '"nomad\.service"' "Service: nomad.service" "$YELLOW"

# User/group names (excluding variable names)
search_pattern 'Owner.*"vault"' "User/Owner: vault" "$YELLOW"
search_pattern 'Group.*"vault"' "Group: vault" "$YELLOW"
search_pattern 'User.*"root"' "User: root" "$YELLOW"

#============================================================
# 5. FILE PERMISSIONS (Octal)
#============================================================

echo -e "\n${BLUE}[5/12] FILE PERMISSIONS${NC}"

search_pattern '\s0755[^0-9]' "Permission: 0755 (rwxr-xr-x)" "$RED"
search_pattern '\s0750[^0-9]' "Permission: 0750 (rwxr-x---)" "$RED"
search_pattern '\s0700[^0-9]' "Permission: 0700 (rwx------)" "$RED"
search_pattern '\s0644[^0-9]' "Permission: 0644 (rw-r--r--)" "$RED"
search_pattern '\s0640[^0-9]' "Permission: 0640 (rw-r-----)" "$RED"
search_pattern '\s0600[^0-9]' "Permission: 0600 (rw-------)" "$RED"

#============================================================
# 6. ENVIRONMENT VARIABLE NAMES
#============================================================

echo -e "\n${BLUE}[6/12] ENVIRONMENT VARIABLE NAMES${NC}"

search_pattern '"VAULT_ADDR"' "Env: VAULT_ADDR" "$YELLOW"
search_pattern '"VAULT_TOKEN"' "Env: VAULT_TOKEN" "$YELLOW"
search_pattern '"CONSUL_HTTP_ADDR"' "Env: CONSUL_HTTP_ADDR" "$YELLOW"
search_pattern '"NOMAD_ADDR"' "Env: NOMAD_ADDR" "$YELLOW"

#============================================================
# 7. URL PATTERNS AND ENDPOINTS
#============================================================

echo -e "\n${BLUE}[7/12] URL PATTERNS AND ENDPOINTS${NC}"

search_pattern '"https://' "URL: https://*" "$YELLOW"
search_pattern '"http://' "URL: http://*" "$YELLOW"
search_pattern '"/v1/' "API Endpoint: /v1/*" "$YELLOW"

#============================================================
# 8. TIMEOUTS AND DURATIONS
#============================================================

echo -e "\n${BLUE}[8/12] TIMEOUTS AND DURATIONS${NC}"

search_pattern '[0-9]\+ \* time\.Second[^a-zA-Z]' "Timeout: N * time.Second" "$YELLOW"
search_pattern '[0-9]\+ \* time\.Minute[^a-zA-Z]' "Timeout: N * time.Minute" "$YELLOW"
search_pattern '[0-9]\+ \* time\.Hour[^a-zA-Z]' "Timeout: N * time.Hour" "$YELLOW"

#============================================================
# 9. RETRY COUNTS AND DELAYS
#============================================================

echo -e "\n${BLUE}[9/12] RETRY COUNTS${NC}"

# This is tricky - need context to avoid false positives
search_pattern 'RetryCount.*=.*[0-9]' "Retry count assignments" "$YELLOW"
search_pattern 'MaxRetries.*=.*[0-9]' "Max retries assignments" "$YELLOW"

#============================================================
# 10. CONSUL/VAULT STORAGE PATHS
#============================================================

echo -e "\n${BLUE}[10/12] STORAGE PATHS (Consul KV/Vault)${NC}"

search_pattern '"secret/' "Vault path: secret/*" "$YELLOW"
search_pattern '"service/' "Consul path: service/*" "$YELLOW"
search_pattern '"vault/' "Storage path: vault/*" "$YELLOW"

#============================================================
# 11. BINARY/COMMAND NAMES
#============================================================

echo -e "\n${BLUE}[11/12] BINARY/COMMAND NAMES${NC}"

search_pattern '"systemctl"' "Command: systemctl" "$YELLOW"
search_pattern '"journalctl"' "Command: journalctl" "$YELLOW"
search_pattern '"docker"' "Command: docker" "$YELLOW"

#============================================================
# 12. CONFIGURATION FILE NAMES
#============================================================

echo -e "\n${BLUE}[12/12] CONFIGURATION FILE NAMES${NC}"

search_pattern '"vault\.hcl"' "Config: vault.hcl" "$YELLOW"
search_pattern '"consul\.hcl"' "Config: consul.hcl" "$YELLOW"
search_pattern '"nomad\.hcl"' "Config: nomad.hcl" "$YELLOW"

#============================================================
# SUMMARY
#============================================================

echo -e "\n${BLUE}============================================================${NC}"
echo -e "${BLUE}AUDIT SUMMARY${NC}"
echo -e "${BLUE}============================================================${NC}"

cat >> "$REPORT_FILE" <<EOF

============================================================
FINAL SUMMARY
============================================================

Total Violations Found: $TOTAL_VIOLATIONS

EOF

if [ $TOTAL_VIOLATIONS -eq 0 ]; then
    echo -e "${GREEN}✓ NO VIOLATIONS FOUND - P0 Rule #11 Compliant!${NC}"
    echo "✓ P0 Rule #11 COMPLIANT - No hardcoded values found" >> "$REPORT_FILE"
else
    echo -e "${RED}✗ $TOTAL_VIOLATIONS VIOLATIONS FOUND${NC}"
    echo "✗ P0 Rule #11 VIOLATION - $TOTAL_VIOLATIONS hardcoded values found" >> "$REPORT_FILE"
    echo ""
    echo -e "${YELLOW}Action Required:${NC}"
    echo "1. Review report: $REPORT_FILE"
    echo "2. Move hardcoded values to constants.go"
    echo "3. Update code to use constants"
    echo "4. Re-run audit to verify compliance"
fi

echo ""
echo "Full report: $REPORT_FILE"
echo ""

exit $TOTAL_VIOLATIONS
