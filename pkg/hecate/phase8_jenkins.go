// pkg/hecate/phase8_jenkins.go

package hecate

import (
	"bufio"
	"fmt"
	"os"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"go.uber.org/zap"
)

// SetupJenkinsWizard prompts the user for Jenkins setup info and returns a ServiceBundle.
func SetupJenkinsWizard(reader *bufio.Reader) ServiceBundle {
	log := zap.L().Named("hecate-jenkins-setup")
	log.Info("🔧 Collecting Jenkins setup information...")

	jenkinsDomain := interaction.PromptInputWithReader("Enter Jenkins domain (e.g., ci.domain.com)", "ci.domain.com", reader)
	backendIP := interaction.PromptInputWithReader("Enter backend IP address for Jenkins (e.g., 192.168.0.10)", "", reader)

	// ==== Compose ====
	serviceSpec := &ServiceSpec{
		FullServiceYAML: `
		  jenkins:
		    image: jenkins/jenkins:lts
		    container_name: hecate-jenkins
		    ports:
		      - "8080:8080"
		      - "50000:50000"
		    volumes:
		      - jenkins_home:/var/jenkins_home
		    networks:
		      - hecate-net
		`,
	}

	composeSpec := &ComposeSpec{
		Services: map[string]*ServiceSpec{
			"jenkins": serviceSpec,
		},
	}

	// ==== Caddy ====
	caddySpec := &CaddySpec{
		Proxies: []CaddyAppProxy{
			{
				AppName:     "jenkins",
				Domain:      jenkinsDomain,
				BackendIP:   backendIP,
				BackendPort: "8080",
			},
		},
	}

	// ==== NGINX ====
	nginxSpec := &NginxSpec{
		StreamBlocks: []NginxStreamBlock{
			{
				UpstreamName: "jenkins_agent",
				BackendPort:  "50000",
				ListenPort:   "50000",
				BackendIP:    backendIP,
			},
		},
		PortsTCP: []string{"50000"},
	}

	log.Info("✅ Jenkins ServiceBundle prepared")
	return ServiceBundle{
		Compose: composeSpec,
		Caddy:   caddySpec,
		Nginx:   nginxSpec,
	}
}

// SetupJenkinsCompose builds and returns the DockerComposeFragment for Jenkins.
func SetupJenkinsCompose(config DockerConfig) (DockerComposeFragment, error) {
	log := zap.L().Named("hecate-jenkins-compose-setup")
	log.Info("🔧 Building Docker Compose fragment for Jenkins (port injection)...")

	// This is only adding port 50000 to the nginx service
	rendered, err := renderTemplateFromString(`
# Jenkins agent port mapping (add under nginx.ports)
      - "50000:50000"
`, config)
	if err != nil {
		log.Error("Failed to render Jenkins Docker Compose fragment", zap.Error(err))
		return DockerComposeFragment{}, fmt.Errorf("failed to render Jenkins Docker Compose: %w", err)
	}

	log.Info("✅ Docker Compose fragment for Jenkins rendered successfully")
	return DockerComposeFragment{
		ServiceYAML: rendered,
	}, nil
}

// RenderJenkinsCompose renders and writes the Jenkins Docker Compose block.
func RenderJenkinsCompose(bundle ServiceBundle) error {
	log := zap.L().Named("hecate-jenkins-compose-render")
	log.Info("🔧 Rendering Jenkins Docker Compose block...")
	for svcName, svc := range bundle.Compose.Services {
		log.Info("🔧 Rendering service", zap.String("service", svcName))
		rendered, err := renderTemplateFromString(svc.FullServiceYAML, svc.Environment)
		if err != nil {
			log.Error("Failed to render service", zap.Error(err),
				zap.String("service", svcName),
			)
			return fmt.Errorf("failed to render service %s: %w", svcName, err)
		}

		dockerComposePath := "./docker-compose.override.yml"
		err = appendToFile(dockerComposePath, rendered)
		if err != nil {
			log.Error("Failed to write Docker Compose block", zap.Error(err),
				zap.String("path", dockerComposePath),
				zap.String("service", svcName),
			)
			return fmt.Errorf("failed to write Docker Compose for service %s: %w", svcName, err)
		}
	}

	log.Info("✅ Jenkins Docker Compose block(s) written successfully")
	return nil
}

// SetupJenkinsCaddy prompts for domain backend info and returns a CaddySpec fragment.
func SetupJenkinsCaddy(reader *bufio.Reader) CaddySpec {
	log := zap.L().Named("hecate-jenkins-caddy-setup")
	log.Info("🔧 Collecting Jenkins Caddy reverse proxy setup information...")

	jenkinsDomain := interaction.PromptInputWithReader("Enter Jenkins domain (e.g., jenkins.domain.com)", "jenkins.domain.com", reader)
	backendIP := interaction.PromptInputWithReader("Enter backend IP address for Jenkins (e.g., 192.168.0.10)", "", reader)

	caddyCfg := CaddySpec{
		Proxies: []CaddyAppProxy{
			{
				AppName:     "jenkins",
				Domain:      jenkinsDomain,
				BackendIP:   backendIP,
				BackendPort: "8080", // Jenkins app port
			},
		},
	}

	log.Info("✅ Jenkins Caddy config fragment prepared",
		zap.String("domain", jenkinsDomain),
		zap.String("backend_ip", backendIP),
	)

	return caddyCfg
}

// RenderJenkinsCaddy renders and writes the Caddyfile block for Jenkins.
func RenderJenkinsCaddy(caddyCfg CaddySpec) error {
	log := zap.L().Named("hecate-jenkins-caddy-render")
	log.Info("🔧 Rendering Jenkins Caddyfile fragment...")

	content, err := RenderCaddyfileContent(caddyCfg)
	if err != nil {
		log.Error("Failed to render Jenkins Caddyfile content", zap.Error(err))
		return fmt.Errorf("failed to render Jenkins Caddyfile: %w", err)
	}

	caddyfilePath := HecateCaddyfile
	err = appendToFile(caddyfilePath, content)
	if err != nil {
		log.Error("Failed to append Jenkins Caddy block", zap.Error(err),
			zap.String("path", caddyfilePath),
		)
		return fmt.Errorf("failed to write Jenkins Caddy block: %w", err)
	}

	log.Info("📝 Jenkins Caddy block appended successfully",
		zap.String("path", caddyfilePath),
	)
	return nil
}

// SetupJenkinsNginx prompts for backend IP and returns an NginxSpec for Jenkins agent port.
func SetupJenkinsNginx(reader *bufio.Reader) *NginxSpec {
	log := zap.L().Named("hecate-jenkins-nginx-setup")
	log.Info("🔧 Collecting Jenkins NGINX stream proxy setup information...")

	backendIP := interaction.PromptInputWithReader("Enter backend IP address for Jenkins agent (e.g., 192.168.0.10)", "", reader)

	nginxSpec := &NginxSpec{
		StreamBlocks: []NginxStreamBlock{
			{
				UpstreamName: "jenkins_agent",
				BackendPort:  "50000",
				ListenPort:   "50000",
				BackendIP:    backendIP,
			},
		},
		PortsTCP: []string{"50000"},
	}

	log.Info("✅ Jenkins NGINX config prepared",
		zap.String("backend_ip", backendIP),
	)

	return nginxSpec
}

// RenderJenkinsNginx renders and writes the NGINX stream block for Jenkins agent port.
func RenderJenkinsNginx(bundle ServiceBundle) error {
	log := zap.L().Named("hecate-jenkins-nginx-render")
	log.Info("🔧 Rendering Jenkins NGINX stream block...")

	streamContent, err := RenderStreamBlocks(
		bundle.Nginx.StreamBlocks[0].BackendIP,
		bundle.Nginx.StreamBlocks,
	)
	if err != nil {
		log.Error("Failed to render Jenkins NGINX stream block", zap.Error(err))
		return fmt.Errorf("failed to render Jenkins NGINX stream block: %w", err)
	}

	targetDir := "./nginx-fragments"
	if err := ensureDir(targetDir); err != nil {
		log.Error("Failed to create NGINX fragments directory", zap.Error(err))
		return fmt.Errorf("failed to create NGINX fragments directory: %w", err)
	}

	filePath := fmt.Sprintf("%s/%s.stream", targetDir, "jenkins")
	err = os.WriteFile(filePath, []byte(streamContent), 0644)
	if err != nil {
		log.Error("Failed to write Jenkins NGINX stream fragment", zap.Error(err),
			zap.String("path", filePath),
		)
		return fmt.Errorf("failed to write Jenkins NGINX stream block: %w", err)
	}

	log.Info("📝 Jenkins NGINX stream block written successfully",
		zap.String("path", filePath),
	)
	return nil
}
