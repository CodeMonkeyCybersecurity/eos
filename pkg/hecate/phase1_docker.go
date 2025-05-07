// pkg/hecate/phase1_docker.go

package hecate

// import (
// 	"bytes"
// 	"os"
// 	"strings"
// 	"text/template"

// 	"go.uber.org/zap"
// )

// // This function allows rendering a full docker-compose.yml from a single DockerConfig. It is kept for batch/automated setups and is NOT used by the wizard/collate flow.

// // CreateDockerComposeFromConfig renders Docker Compose using provided config and writes it to disk.
// func CreateDockerComposeFromConfig(cfg DockerConfig) error {
// 	log := zap.L().Named("create-docker-compose-config")
// 	log.Info("🚀 Rendering Docker Compose file from provided config...")

// 	// Parse & execute the template
// 	tmpl, err := template.New("docker-compose").Parse(HecateServiceTemplate)
// 	if err != nil {
// 		log.Error("Failed to parse Docker Compose template", zap.Error(err))
// 		return err
// 	}

// 	var rendered bytes.Buffer
// 	if err := tmpl.Execute(&rendered, cfg); err != nil {
// 		log.Error("Failed to render Docker Compose template", zap.Error(err))
// 		return err
// 	}

// 	// Write to docker-compose.yml
// 	outputPath := "docker-compose.yml"
// 	if err := os.WriteFile(outputPath, rendered.Bytes(), 0644); err != nil {
// 		log.Error("Failed to write docker-compose.yml", zap.Error(err))
// 		return err
// 	}

// 	// Move to /opt/hecate
// 	if err := MoveDockerComposeToHecate(); err != nil {
// 		log.Error("Failed to move docker-compose.yml into /opt/hecate", zap.Error(err))
// 		return err
// 	}

// 	log.Info("✅ Docker Compose file rendered and saved", zap.String("path", outputPath))
// 	return nil
// }


// func BuildDockerCompose(cfg DockerConfig, includeCoturn, includeKeycloak, includeNginx bool) (string, error) {
// 	var composeParts []string

// 	// Always include Caddy (?)
// 	caddySection, err := RenderCaddySection(cfg)
// 	if err != nil {
// 		return "", err
// 	}
// 	composeParts = append(composeParts, caddySection)

// 	if includeNginx {
// 		nginxSection, err := RenderNginxSection(cfg)
// 		if err != nil {
// 			return "", err
// 		}
// 		composeParts = append(composeParts, nginxSection)
// 	}

// 	if includeCoturn {
// 		coturnSection, err := RenderCoturnSection(cfg)
// 		if err != nil {
// 			return "", err
// 		}
// 		composeParts = append(composeParts, coturnSection)
// 	}

// 	if includeKeycloak {
// 		keycloakSection, err := RenderKeycloakSection(cfg)
// 		if err != nil {
// 			return "", err
// 		}
// 		composeParts = append(composeParts, keycloakSection)
// 	}

// 	// Add networks/volumes at the end
// 	networksSection := RenderNetworksSection()
// 	composeParts = append(composeParts, networksSection)

// 	// Combine
// 	return strings.Join(composeParts, "\n\n"), nil
// }

// func RenderDockerCompose(config DockerConfig) (string, error) {
// 	var buf bytes.Buffer

// 	// Always add Caddy
// 	buf.WriteString("# Generated Hecate configuration for " + config.AppName + "\nservices:\n")

// 	// Render Caddy
// 	buf.WriteString(DockerCaddyService)

// 	tmpl := template.New("hecate")

// 	// Conditional: Nginx
// 	if config.NginxEnabled {
// 		t, err := tmpl.Parse(DockerNginxService)
// 		if err != nil {
// 			return "", err
// 		}
// 		if err := t.Execute(&buf, config); err != nil {
// 			return "", err
// 		}
// 	}

// 	// Conditional: Coturn
// 	if config.CoturnEnabled {
// 		t, err := tmpl.Parse(DockerCoturnService)
// 		if err != nil {
// 			return "", err
// 		}
// 		if err := t.Execute(&buf, config); err != nil {
// 			return "", err
// 		}
// 	}

// 	// Conditional: Keycloak
// 	if config.KeycloakEnabled {
// 		t, err := tmpl.Parse(DockerKeycloakService)
// 		if err != nil {
// 			return "", err
// 		}
// 		if err := t.Execute(&buf, config); err != nil {
// 			return "", err
// 		}
// 	}

// 	// Add networks & volumes
// 	buf.WriteString(DockerNetworkAndVolumes)

// 	return buf.String(), nil
// }
//
