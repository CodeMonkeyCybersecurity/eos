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

	// === New: Service selection ===
	setupKeycloak := interaction.PromptInputWithReader("Do you want to set up Keycloak? (yes/no)", "yes", reader)
	setupNextcloud := interaction.PromptInputWithReader("Do you want to set up Nextcloud? (yes/no)", "no", reader)
	setupWazuh := interaction.PromptInputWithReader("Do you want to set up Wazuh? (yes/no)", "no", reader)
	setupMailcow := interaction.PromptInputWithReader("Do you want to set up Mailcow? (yes/no)", "no", reader)

	if strings.ToLower(setupKeycloak) != "yes" &&
		strings.ToLower(setupNextcloud) != "yes" &&
		strings.ToLower(setupWazuh) != "yes" &&
		strings.ToLower(setupMailcow) != "yes" {
		log.Warn("🚫 No services selected for setup. Only reverse proxy config will be applied.")
	}

	var dockerCfg *DockerConfig
	var allCaddyApps []CaddyConfig

	// === Keycloak ===
	if strings.ToLower(setupKeycloak) == "yes" {
		kDockerCfg, kCaddyCfg := SetupKeycloak(reader)
		dockerCfg = kDockerCfg
		allCaddyApps = append(allCaddyApps, kCaddyCfg.Apps...)
	}

	// === Other services ===
	if strings.ToLower(setupNextcloud) == "yes" ||
		strings.ToLower(setupWazuh) == "yes" ||
		strings.ToLower(setupMailcow) == "yes" {

		backendIP := interaction.PromptInputWithReader("Enter backend IP address (e.g., 192.168.0.1)", "", reader)
		log.Info("🚧 Nextcloud, Wazuh, and Mailcow setup not yet implemented")

		// You would later: append CaddyConfig for these too
		_ = backendIP // prevent unused var error for now
	}

	caddyCfg := CaddyConfig{
		Apps: allCaddyApps,
	}

	log.Info("🚀 Running full Hecate setup now...")

	err := SetupFullHecateEnvironment(
		reader,
		dockerCfg, // pass *DockerConfig or nil
		caddyCfg,
		"", // backendIP no longer needed globally
	)
	if err != nil {
		log.Error("❌ Hecate setup failed", zap.Error(err))
		return err
	}

	log.Info("✅ Hecate setup completed successfully!")
	return nil
}

// SetupFullHecateEnvironment orchestrates the full Hecate setup: Docker Compose, Caddy, and Nginx.
func SetupFullHecateEnvironment(reader *bufio.Reader, dockerCfg *DockerConfig, caddyCfg CaddyConfig, backendIP string) error {
	log := zap.L().Named("hecate-full-setup")
	log.Info("🚀 Starting full Hecate setup (Docker + Caddy + Nginx)...")

	if err := EnsureHecateDirExists(); err != nil {
		log.Error("Failed to ensure /opt/hecate exists", zap.Error(err))
		return err
	}

	// Phase 1: Docker Compose setup
	if dockerCfg != nil {
		log.Info("🔧 Phase 1: Docker Compose setup")
		if err := CreateDockerComposeFromConfig(*dockerCfg); err != nil {
			log.Error("❌ Failed during Docker Compose setup", zap.Error(err))
			return err
		}
	} else {
		log.Warn("🚫 Skipping Docker Compose setup (no services selected)")
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

func SetupKeycloak(reader *bufio.Reader) (*DockerConfig, CaddyConfig) {
	log := zap.L().Named("hecate-keycloak-setup")
	log.Info("🔧 Collecting Keycloak setup information...")

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

	dockerCfg := &DockerConfig{
		AppName:               "keycloak",
		TCPPorts:              tcpPorts,
		UDPPorts:              udpPorts,
		NginxEnabled:          true,
		CoturnEnabled:         true,
		CoturnAuthSecret:      coturnAuthSecret,
		KeycloakDomain:        keycloakDomain,
		KeycloakDBName:        keycloakDBName,
		KeycloakDBUser:        keycloakDBUser,
		KeycloakDBPassword:    keycloakDBPassword,
		KeycloakAdminUser:     keycloakAdminUser,
		KeycloakAdminPassword: keycloakAdminPassword,
	}

	caddyCfg := CaddyConfig{
		Apps: []CaddyConfig{
			{
				AppName:   "keycloak",
				Domain:    keycloakDomain,
				BackendIP: "keycloak", // Docker service name or "localhost"
			},
		},
		KeycloakDomain: keycloakDomain,
	}

	return dockerCfg, caddyCfg
}
