// pkg/hecate/lifecycle_create.go

package hecate

import (
	"bufio"
	"os"
	"strings"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/parse"
	"go.uber.org/zap"
)

func SetupHecateWithPrompts() error {
	log := zap.L().Named("hecate-full-setup-prompt")
	reader := bufio.NewReader(os.Stdin)

	log.Info("🚀 Welcome to the Hecate full setup wizard!")

	// === Phase 1: Collect Docker Compose info ===
	appName := interaction.PromptInputWithReader("Enter the main app name (e.g., wazuh, mailcow, jenkins)", "", reader)

	keycloakDomain := interaction.PromptInputWithReader("Enter Keycloak domain (e.g., hera.domain.com)", "hera.domain.com", reader)
	keycloakDBName := interaction.PromptInputWithReader("Enter Keycloak DB name", "keycloak", reader)
	keycloakDBUser := interaction.PromptInputWithReader("Enter Keycloak DB user", "keycloak", reader)
	keycloakDBPassword := interaction.PromptInputWithReader("Enter Keycloak DB password", "changeme1", reader)
	keycloakAdminUser := interaction.PromptInputWithReader("Enter Keycloak admin user", "admin", reader)
	keycloakAdminPassword := interaction.PromptInputWithReader("Enter Keycloak admin password", "changeme", reader)

	coturnAuthSecret := interaction.PromptInputWithReader("Enter Coturn auth secret (for TURN server)", "change_me", reader)

	tcpPortsInput := interaction.PromptInputWithReader("Enter TCP ports (comma-separated, e.g., 1515,1514,55000)", "", reader)
	tcpPorts := parse.SplitAndTrim(tcpPortsInput)

	udpPortsInput := interaction.PromptInputWithReader("Enter UDP ports (comma-separated, e.g., 1514)", "", reader)
	udpPorts := parse.SplitAndTrim(udpPortsInput)

	backendIP := interaction.PromptInputWithReader("Enter backend IP address (e.g., 192.168.0.1)", "", reader)

	// ✅ Build the DockerConfig
	dockerCfg := DockerConfig{
		AppName:               appName,
		TCPPorts:              tcpPorts,
		UDPPorts:              udpPorts,
		NginxEnabled:          true, // You could make this prompt-driven if needed
		CoturnEnabled:         true,
		CoturnAuthSecret:      coturnAuthSecret,
		KeycloakDomain:        keycloakDomain,
		KeycloakDBName:        keycloakDBName,
		KeycloakDBUser:        keycloakDBUser,
		KeycloakDBPassword:    keycloakDBPassword,
		KeycloakAdminUser:     keycloakAdminUser,
		KeycloakAdminPassword: keycloakAdminPassword,
	}

	// === Phase 2: Collect Caddy reverse proxy apps ===
	var caddyApps []CaddyConfig

	for {
		addMore := interaction.PromptInputWithReader("Do you want to add a reverse proxy app? (yes/no)", "no", reader)
		if strings.ToLower(addMore) != "yes" {
			break
		}

		app := interaction.PromptInputWithReader("Enter app name (e.g., wazuh, mailcow, nextcloud)", "", reader)
		domain := interaction.PromptInputWithReader("Enter domain (e.g., myapp.cybermonkey.dev)", "", reader)
		subdomain := interaction.PromptInputWithReader("Enter subdomain (optional, press Enter to skip)", "", reader)
		appBackendIP := interaction.PromptInputWithReader("Enter backend IP for this app", backendIP, reader)

		caddyApps = append(caddyApps, CaddyConfig{
			AppName:   app,
			Domain:    domain,
			Subdomain: subdomain,
			BackendIP: appBackendIP,
		})

		log.Info("✅ Added reverse proxy app", zap.String("app", app), zap.String("domain", domain))
	}

	// === Prepare CaddyConfig for the orchestrator ===
	caddyCfg := CaddyConfig{
		Apps:           caddyApps,
		KeycloakDomain: keycloakDomain,
	}

	// === Orchestrate everything ===
	log.Info("🚀 Running full Hecate setup now...")

	err := SetupFullHecateEnvironment(
		reader,
		dockerCfg, // ✅ pass the docker config
		caddyCfg,
		backendIP,
	)
	if err != nil {
		log.Error("❌ Hecate setup failed", zap.Error(err))
		return err
	}

	log.Info("✅ Hecate setup completed successfully!")
	return nil
}

// SetupFullHecateEnvironment orchestrates the full Hecate setup: Docker Compose, Caddy, and Nginx.
func SetupFullHecateEnvironment(reader *bufio.Reader, dockerCfg DockerConfig, caddyCfg CaddyConfig, backendIP string) error {
	log := zap.L().Named("hecate-full-setup")
	log.Info("🚀 Starting full Hecate setup (Docker + Caddy + Nginx)...")

	// Phase 1: Docker Compose setup
	log.Info("🔧 Phase 1: Docker Compose setup")
	if err := CreateDockerComposeFromConfig(dockerCfg); err != nil { // ✅ use config
		log.Error("❌ Failed during Docker Compose setup", zap.Error(err))
		return err
	}

	// Phase 2: Caddy setup
	log.Info("🔧 Phase 2: Caddy setup")
	if err := SetupCaddyEnvironment(caddyCfg); err != nil {
		log.Error("❌ Failed during Caddy setup", zap.Error(err))
		return err
	}

	// Phase 3: Nginx setup
	log.Info("🔧 Phase 3: Nginx setup")
	if err := SetupNginxEnvironment(backendIP); err != nil {
		log.Error("❌ Failed during Nginx setup", zap.Error(err))
		return err
	}

	log.Info("✅ Full Hecate environment setup completed successfully!")
	return nil
}
