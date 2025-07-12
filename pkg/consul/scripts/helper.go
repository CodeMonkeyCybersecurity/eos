package scripts

import (
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// CreateHelper creates the consul-vault-helper script
// Migrated from cmd/create/consul.go createConsulHelperScript
func CreateHelper(rc *eos_io.RuntimeContext) error {
	log := otelzap.Ctx(rc.Ctx)

	// ASSESS - Prepare helper script
	log.Info("Assessing Consul helper script requirements")

	// INTERVENE - Create helper script
	log.Info("Creating Consul helper script")

	helperScript := fmt.Sprintf(`#!/bin/bash
# /usr/local/bin/consul-vault-helper
# Consul and Vault integration helper script

CONSUL_ADDR="http://localhost:%d"
VAULT_ADDR="${VAULT_ADDR:-https://localhost:8200}"

case "$1" in
  status)
    echo "=== Consul Status ==="
    curl -s $CONSUL_ADDR/v1/status/leader || echo "Consul not responding"
    echo -e "\n=== Vault Service Health ==="
    curl -s $CONSUL_ADDR/v1/health/service/vault | jq -r '.[].Checks[]? | "\(.Name): \(.Status)"' 2>/dev/null || echo "No Vault service registered"
    ;;
    
  discover)
    echo "=== Discovering Vault via DNS ==="
    dig +short @127.0.0.1 -p 8600 vault.service.consul 2>/dev/null || echo "DNS lookup failed"
    echo -e "\n=== Discovering Vault via API ==="
    curl -s $CONSUL_ADDR/v1/catalog/service/vault | jq -r '.[].ServiceAddress + ":" + (.[].ServicePort | tostring)' 2>/dev/null || echo "API lookup failed"
    ;;
    
  watch)
    export CONSUL_HTTP_ADDR=$CONSUL_ADDR
    consul watch -type=service -service=vault jq . 2>/dev/null || echo "Watch failed - check consul installation"
    ;;
    
  register-app)
    # Example: Register a new app that uses Vault
    APP_NAME=$2
    APP_PORT=$3
    if [ -z "$APP_NAME" ] || [ -z "$APP_PORT" ]; then
      echo "Usage: $0 register-app <app-name> <port>"
      exit 1
    fi
    
    cat > /tmp/${APP_NAME}-service.json << EOF
{
  "service": {
    "name": "${APP_NAME}",
    "port": ${APP_PORT},
    "tags": ["vault-aware", "eos-managed"],
    "checks": [{
      "http": "http://localhost:${APP_PORT}/health",
      "interval": "10s"
    }]
  }
}
EOF
    curl -X PUT -d @/tmp/${APP_NAME}-service.json $CONSUL_ADDR/v1/agent/service/register
    echo "Registered service: $APP_NAME on port $APP_PORT"
    rm -f /tmp/${APP_NAME}-service.json
    ;;
    
  services)
    echo "=== All Registered Services ==="
    curl -s $CONSUL_ADDR/v1/catalog/services | jq -r 'keys[]' 2>/dev/null || echo "Failed to list services"
    ;;
    
  nodes)
    echo "=== Cluster Nodes ==="
    curl -s $CONSUL_ADDR/v1/catalog/nodes | jq -r '.[].Node' 2>/dev/null || echo "Failed to list nodes"
    ;;
    
  *)
    echo "Usage: $0 {status|discover|watch|register-app|services|nodes}"
    echo ""
    echo "Commands:"
    echo "  status       - Show Consul and Vault health status"
    echo "  discover     - Test service discovery for Vault"
    echo "  watch        - Watch Vault service changes"
    echo "  register-app - Register a new service with Consul"
    echo "  services     - List all registered services"
    echo "  nodes        - List all cluster nodes"
    echo ""
    echo "Environment:"
    echo "  CONSUL_ADDR: $CONSUL_ADDR"
    echo "  VAULT_ADDR:  $VAULT_ADDR"
    ;;
esac`, shared.PortConsul)

	scriptPath := "/usr/local/bin/consul-vault-helper"
	if err := os.WriteFile(scriptPath, []byte(helperScript), 0755); err != nil {
		return fmt.Errorf("failed to write helper script: %w", err)
	}

	// EVALUATE - Verify script was created properly
	log.Info("Evaluating Consul helper script creation")

	// Check if script exists with correct permissions
	info, err := os.Stat(scriptPath)
	if err != nil {
		return fmt.Errorf("failed to verify helper script: %w", err)
	}

	if info.Mode().Perm() != 0755 {
		return fmt.Errorf("helper script has incorrect permissions: expected 0755, got %s", info.Mode().Perm())
	}

	// Verify script is executable
	if info.Mode()&0111 == 0 {
		return fmt.Errorf("helper script is not executable")
	}

	log.Info("Consul helper script created successfully",
		zap.String("path", scriptPath),
		zap.String("permissions", info.Mode().String()))

	return nil
}
