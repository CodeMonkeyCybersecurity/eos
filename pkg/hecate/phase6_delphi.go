// pkg/hecate/phase6_delphi.go

package hecate

import (
	"bufio"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"go.uber.org/zap"
)

// SetupWazuhWizard prompts the user for Wazuh setup info and returns a ServiceBundle.
func SetupWazuhWizard(reader *bufio.Reader) ServiceBundle {
	log := zap.L().Named("hecate-wazuh-setup")
	log.Info("🔧 Collecting Wazuh setup information...")

	// Prompt user for domain and backend IP
	wazuhDomain := interaction.PromptInputWithReader("Enter Wazuh domain (e.g., delphi.domain.com)", "delphi.domain.com", reader)
	backendIP := interaction.PromptInputWithReader("Enter backend IP address for Wazuh (e.g., 192.168.0.10)", "", reader)

	// ==== Compose ====
	composeSpec := &ServiceSpec{
		Name:            "wazuh",
		FullServiceYAML: DockerNginxService,
		Ports:           []string{"1515", "1514", "55000"},
	}

	// ==== Caddy ====
	caddySpec := &CaddySpec{
		Proxies: []CaddyAppProxy{
			{
				AppName:     "wazuh",
				Domain:      wazuhDomain,
				BackendIP:   backendIP,
				BackendPort: "443",
			},
		},
	}

	// ==== Nginx ====
	nginxSpec := &NginxSpec{
		StreamBlocks: WazuhStreamBlocks,
		PortsTCP:     []string{"1515", "1514", "55000"},
		PortsUDP:     []string{"1514"},
	}

	log.Info("✅ Wazuh ServiceBundle prepared")
	compose := &ComposeSpec{
		Services: map[string]*ServiceSpec{
			"wazuh": composeSpec,
		},
	}

	return ServiceBundle{
		Compose: compose,
		Caddy:   caddySpec,
		Nginx:   nginxSpec,
	}
}

// SetupDelphiNginx prepares the NGINX config fragment for Wazuh.
func SetupDelphiNginx(backendIP string) (NginxFragment, error) {
	log := zap.L().Named("hecate-wazuh-nginx-setup")
	log.Info("🔧 Preparing NGINX stream config for Wazuh...",
		zap.String("backend_ip", backendIP),
	)

	// Render the Wazuh stream blocks using the helper
	streamContent, err := RenderStreamBlocks(backendIP, WazuhStreamBlocks)
	if err != nil {
		log.Error("❌ Failed to render Wazuh NGINX stream blocks", zap.Error(err))
		return NginxFragment{}, err
	}

	// Wrap in an NginxFragment struct
	fragment := NginxFragment{
		ServiceName: "wazuh",
		StreamBlock: streamContent,
	}

	log.Info("✅ Wazuh NGINX fragment prepared successfully")
	return fragment, nil
}

// RenderDelphiNginx renders and writes the Wazuh NGINX stream block.
func RenderDelphiNginx(bundle ServiceBundle) error {
	log := zap.L().Named("hecate-wazuh-nginx-render")

	// Render all stream blocks (dynamic backend IP can be handled later if needed)
	// Here we assume backendIP is set in each block via wizard
	rendered, err := RenderStreamBlocks("127.0.0.1", bundle.Nginx.StreamBlocks)
	if err != nil {
		log.Error("Failed to render NGINX stream blocks", zap.Error(err))
		return fmt.Errorf("failed to render NGINX stream blocks: %w", err)
	}

	targetDir := "./assets/conf.d/stream"
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		log.Error("Failed to create stream config directory", zap.Error(err))
		return fmt.Errorf("failed to create directory %s: %w", targetDir, err)
	}

	filePath := fmt.Sprintf("%s/%s.conf", targetDir, "wazuh")
	err = os.WriteFile(filePath, []byte(rendered), 0644)
	if err != nil {
		log.Error("Failed to write NGINX stream block", zap.Error(err),
			zap.String("path", filePath),
		)
		return fmt.Errorf("failed to write NGINX fragment: %w", err)
	}

	log.Info("✅ Wazuh NGINX stream block written successfully",
		zap.String("path", filePath),
	)
	return nil
}

// SetupDelphiCompose builds and returns the DockerComposeFragment for Wazuh (Delphi).
// This ONLY updates the nginx service block to expose Wazuh ports.
func SetupDelphiCompose(config DockerConfig) (DockerComposeFragment, error) {
	log := zap.L().Named("hecate-delphi-compose-setup")
	log.Info("🔧 Building Docker Compose fragment to expose Wazuh (Delphi) ports via NGINX...")

	// Inject Wazuh ports into the DockerConfig (if not already injected earlier)
	InjectWazuhPorts(&config)

	// Render only the nginx service block with the updated ports
	rendered, err := renderTemplateFromString(DockerNginxService, config)
	if err != nil {
		log.Error("Failed to render Docker Compose nginx service block", zap.Error(err))
		return DockerComposeFragment{}, fmt.Errorf("failed to render nginx Docker Compose for Wazuh ports: %w", err)
	}

	log.Info("✅ Docker Compose nginx service block rendered with Wazuh ports")
	return DockerComposeFragment{
		ServiceYAML: rendered,
	}, nil
}

// RenderDelphiCompose renders and writes the Docker Compose block for Wazuh.
func RenderDelphiCompose(bundle ServiceBundle) error {
	log := zap.L().Named("hecate-delphi-compose-render")
	if bundle.Compose == nil || bundle.Compose.Services == nil {
		log.Warn("No Compose services found in bundle")
		return nil
	}

	for name, svc := range bundle.Compose.Services {
		log.Info("🔧 Rendering Docker Compose block for Delphi service...",
			zap.String("service", name),
		)
		rendered, err := renderTemplateFromString(svc.FullServiceYAML, svc.Environment)
		if err != nil {
			log.Error("Failed to render Docker Compose content", zap.String("service", name), zap.Error(err))
			return err
		}
		dockerComposePath := "./docker-compose.override.yml"
		err = appendToFile(dockerComposePath, rendered)
		if err != nil {
			log.Error("Failed to write Docker Compose block", zap.String("service", name), zap.Error(err),
				zap.String("path", dockerComposePath),
			)
			return fmt.Errorf("failed to write Docker Compose: %w", err)
		}
		log.Info("📝 Docker Compose block written successfully",
			zap.String("service", name),
			zap.String("path", dockerComposePath),
		)
	}
	return nil
}

// SetupDelphiCaddy prepares the CaddyConfig fragment for Wazuh (Delphi).
func SetupDelphiCaddy(reader *bufio.Reader) (CaddyConfig, error) {
	log := zap.L().Named("hecate-delphi-caddy-setup")
	log.Info("🔧 Collecting Caddy reverse proxy info for Wazuh (Delphi)...")

	// Prompt user for domain and backend IP
	wazuhDomain := interaction.PromptInputWithReader("Enter Wazuh domain (e.g., delphi.domain.com)", "delphi.domain.com", reader)
	backendIP := interaction.PromptInputWithReader("Enter backend IP address for Wazuh (e.g., 192.168.0.10)", "", reader)
	backendPort := interaction.PromptInputWithReader("Enter backend port for Wazuh (default 443)", "443", reader)

	caddyCfg := CaddyConfig{
		Proxies: []CaddyAppProxy{
			{
				AppName:     "wazuh",
				Domain:      wazuhDomain,
				BackendIP:   backendIP,
				BackendPort: backendPort,
			},
		},
	}

	log.Info("✅ Wazuh Caddy fragment prepared",
		zap.String("domain", wazuhDomain),
		zap.String("backend_ip", backendIP),
		zap.String("backend_port", backendPort),
	)
	return caddyCfg, nil
}

// InjectWazuhPorts appends Wazuh TCP and UDP ports to the DockerConfig.
func InjectWazuhPorts(cfg *DockerConfig) {
	wazuhTCP := []string{"1515", "1514", "55000"} // standard Wazuh TCP ports
	wazuhUDP := []string{"1514"}                  // Wazuh uses 1514 UDP typically

	cfg.TCPPorts = append(cfg.TCPPorts, wazuhTCP...)
	cfg.UDPPorts = append(cfg.UDPPorts, wazuhUDP...)

	zap.L().Named("hecate-wazuh-inject").Info("Injected Wazuh TCP/UDP ports",
		zap.Strings("tcp_ports", wazuhTCP),
		zap.Strings("udp_ports", wazuhUDP),
	)
}

// RenderDelphiCaddy renders and writes the Caddyfile block for Wazuh.
func RenderDelphiCaddy(bundle ServiceBundle) error {
	log := zap.L().Named("hecate-delphi-caddy-render")

	caddyCfg := CaddyConfig{
		Proxies: bundle.Caddy.Proxies,
	}

	renderedContent, err := RenderCaddyfileContent(caddyCfg)
	if err != nil {
		log.Error("Failed to render Caddyfile fragment for Wazuh", zap.Error(err))
		return fmt.Errorf("failed to render Caddyfile fragment: %w", err)
	}

	targetDir := "./Caddy-fragments"
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		log.Error("Failed to create Caddy fragments directory", zap.Error(err))
		return fmt.Errorf("failed to create Caddy fragments directory: %w", err)
	}

	filePath := fmt.Sprintf("%s/%s.caddy", targetDir, "delphi")
	err = os.WriteFile(filePath, []byte(renderedContent), 0644)
	if err != nil {
		log.Error("Failed to write Wazuh Caddy fragment", zap.Error(err),
			zap.String("path", filePath),
		)
		return fmt.Errorf("failed to write Caddy fragment: %w", err)
	}

	log.Info("✅ Wazuh Caddy fragment written successfully",
		zap.String("path", filePath),
	)
	return nil
}
