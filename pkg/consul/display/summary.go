package display

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_unix"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// InstallationSummary displays the Consul installation summary
// Migrated from cmd/create/consul.go displayInstallationSummary
func InstallationSummary(rc *eos_io.RuntimeContext, vaultAvailable bool) {
	log := otelzap.Ctx(rc.Ctx)

	hostname := eos_unix.GetInternalHostname()

	// Log structured summary
	log.Info("Consul installation completed successfully",
		zap.String("hostname", hostname),
		zap.Int("http_port", shared.PortConsul),
		zap.Bool("vault_integration", vaultAvailable))

	// Display user-friendly summary
	log.Info(" ")
	log.Info("╔══════════════════════════════════════════════════════════════════╗")
	log.Info("║                   CONSUL INSTALLATION COMPLETE                     ║")
	log.Info("╚══════════════════════════════════════════════════════════════════╝")
	log.Info(" ")
	log.Info(" Access Points:")
	log.Info(fmt.Sprintf("   • Web UI:        http://%s:%d/ui", hostname, shared.PortConsul))
	log.Info(fmt.Sprintf("   • HTTP API:      http://%s:%d", hostname, shared.PortConsul))
	log.Info("   • DNS Interface: port 8600") // Standard Consul DNS port
	log.Info(" ")
	log.Info(" Quick Commands:")
	log.Info("   • Check status:      consul-vault-helper status")
	log.Info("   • List services:     consul-vault-helper services")
	log.Info("   • Register service:  consul-vault-helper register-app <name> <port>")
	log.Info(" ")

	if vaultAvailable {
		log.Info(" Vault Integration: ENABLED")
		log.Info("   • Vault is registered as a Consul service")
		log.Info("   • Service discovery: consul-vault-helper discover")
	} else {
		log.Info("  Vault Integration: Not configured")
		log.Info("   • Install Vault to enable service discovery integration")
	}

	log.Info(" ")
	log.Info("📚 Configuration Files:")
	log.Info("   • Main config:    /etc/consul.d/consul.hcl")
	if vaultAvailable {
		log.Info("   • Vault service:  /etc/consul.d/vault-service.json")
	}
	log.Info("   • Data directory: /opt/consul")
	log.Info(" ")
	log.Info(" Next Steps:")
	log.Info("   1. Access the Web UI to explore service discovery")
	log.Info("   2. Register your applications with Consul")
	log.Info("   3. Use DNS interface for service lookups: dig @localhost -p 8600 <service>.service.consul")

	if !vaultAvailable {
		log.Info("   4. Consider installing Vault for secrets management integration")
	}

	log.Info(" ")
	log.Info("═══════════════════════════════════════════════════════════════════")
}
