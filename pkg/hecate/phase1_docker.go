// pkg/hecate/phase1_docker.go

package hecate

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/interaction"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/parse"

	"go.uber.org/zap"
)


// CreateDockerComposeFromConfig renders Docker Compose using provided config and writes it to disk.
func CreateDockerComposeFromConfig(cfg DockerConfig) error {
	log := zap.L().Named("create-docker-compose-config")
	log.Info("🚀 Rendering Docker Compose file from provided config...")

	// Parse & execute the template
	tmpl, err := template.New("docker-compose").Parse(HecateServiceTemplate)
	if err != nil {
		log.Error("Failed to parse Docker Compose template", zap.Error(err))
		return err
	}

	var rendered bytes.Buffer
	if err := tmpl.Execute(&rendered, cfg); err != nil {
		log.Error("Failed to render Docker Compose template", zap.Error(err))
		return err
	}

	// Write to docker-compose.yml
	outputPath := "docker-compose.yml"
	if err := os.WriteFile(outputPath, rendered.Bytes(), 0644); err != nil {
		log.Error("Failed to write docker-compose.yml", zap.Error(err))
		return err
	}

	// Move to /opt/hecate
	if err := MoveDockerComposeToHecate(); err != nil {
		log.Error("Failed to move docker-compose.yml into /opt/hecate", zap.Error(err))
		return err
	}

	log.Info("✅ Docker Compose file rendered and saved", zap.String("path", outputPath))
	return nil
}

func EnsureHecateDirExists() error {
	hecateDir := "/opt/hecate"
	log := zap.L().Named("hecate-setup")

	if _, err := os.Stat(hecateDir); os.IsNotExist(err) {
		log.Info("Directory /opt/hecate does not exist, creating it...")
		if err := os.MkdirAll(hecateDir, 0755); err != nil {
			log.Error("Failed to create /opt/hecate", zap.Error(err))
			return err
		}
		log.Info("✅ /opt/hecate directory created successfully")
	} else {
		log.Info("/opt/hecate directory already exists")
	}
	return nil
}

// RenderDockerCompose prompts the user for required inputs, renders the Docker Compose template, and writes it to disk.
// RenderDockerCompose prompts the user for required inputs, renders the Docker Compose template, and writes it to disk.
func RenderDockerCompose(reader *bufio.Reader) {
	log := zap.L().Named("render-docker-compose")

	log.Info("Starting Docker Compose rendering...")

	// Prompt for all required values (✅ patched: removed extra argument)
	appName := interaction.PromptInputWithReader("Enter the app name (e.g., wazuh, mailcow, jenkins)", "", reader)

	nginxEnabledStr := interaction.PromptInputWithReader("Enable Nginx? (yes/no)", "yes", reader)
	nginxEnabled := strings.ToLower(nginxEnabledStr) == "yes"

	coturnEnabledStr := interaction.PromptInputWithReader("Enable Coturn? (yes/no)", "no", reader)
	coturnEnabled := strings.ToLower(coturnEnabledStr) == "yes"

	keycloakDomain := interaction.PromptInputWithReader("Enter Keycloak domain (e.g., hera.domain.com)", "hera.domain.com", reader)
	keycloakDBName := interaction.PromptInputWithReader("Enter Keycloak DB name", "keycloak", reader)
	keycloakDBUser := interaction.PromptInputWithReader("Enter Keycloak DB user", "keycloak", reader)
	keycloakDBPassword := interaction.PromptInputWithReader("Enter Keycloak DB password", "changeme1", reader)
	keycloakAdminUser := interaction.PromptInputWithReader("Enter Keycloak admin user", "admin", reader)
	keycloakAdminPassword := interaction.PromptInputWithReader("Enter Keycloak admin password", "changeme", reader)

	coturnAuthSecret := interaction.PromptInputWithReader("Enter Coturn auth secret (used in TURN config)", "change_me", reader)

	// Ask for TCP/UDP ports (comma-separated)
	tcpPortsInput := interaction.PromptInputWithReader("Enter TCP ports (comma-separated, e.g., 1515,1514,55000)", "", reader)
	tcpPorts := parse.SplitAndTrim(tcpPortsInput)

	udpPortsInput := interaction.PromptInputWithReader("Enter UDP ports (comma-separated, e.g., 1514)", "", reader)
	udpPorts := parse.SplitAndTrim(udpPortsInput)

	// Prepare the config struct
	cfg := DockerConfig{
		AppName:               appName,
		TCPPorts:              tcpPorts,
		UDPPorts:              udpPorts,
		NginxEnabled:          nginxEnabled,
		CoturnEnabled:         coturnEnabled,
		CoturnAuthSecret:      coturnAuthSecret,
		KeycloakDomain:        keycloakDomain,
		KeycloakDBName:        keycloakDBName,
		KeycloakDBUser:        keycloakDBUser,
		KeycloakDBPassword:    keycloakDBPassword,
		KeycloakAdminUser:     keycloakAdminUser,
		KeycloakAdminPassword: keycloakAdminPassword,
	}

	// Parse & execute the template
	tmpl, err := template.New("docker-compose").Parse(HecateServiceTemplate)
	if err != nil {
		log.Fatal("Failed to parse Docker Compose template", zap.Error(err))
		return
	}

	var rendered bytes.Buffer
	if err := tmpl.Execute(&rendered, cfg); err != nil {
		log.Fatal("Failed to render Docker Compose template", zap.Error(err))
		return
	}

	// Write to docker-compose.yml
	outputPath := "docker-compose.yml"
	if err := os.WriteFile(outputPath, rendered.Bytes(), 0644); err != nil {
		log.Fatal("Failed to write docker-compose.yml", zap.Error(err))
		return
	}

	log.Info("✅ Docker Compose file rendered and saved", zap.String("path", outputPath))
}

func MoveDockerComposeToHecate() error {
	sourcePath := "docker-compose.yml"
	destDir := "/opt/hecate"
	destPath := filepath.Join(destDir, "docker-compose.yml")

	log := zap.L().Named("hecate-setup")

	// Open source file
	srcFile, err := os.Open(sourcePath)
	if err != nil {
		log.Error("Failed to open source docker-compose.yml", zap.Error(err))
		return fmt.Errorf("failed to open %s: %w", sourcePath, err)
	}
	defer srcFile.Close()

	// Create destination file
	destFile, err := os.Create(destPath)
	if err != nil {
		log.Error("Failed to create destination docker-compose.yml", zap.Error(err))
		return fmt.Errorf("failed to create %s: %w", destPath, err)
	}
	defer destFile.Close()

	// Copy contents
	if _, err := io.Copy(destFile, srcFile); err != nil {
		log.Error("Failed to copy docker-compose.yml to /opt/hecate", zap.Error(err))
		return fmt.Errorf("failed to copy to %s: %w", destPath, err)
	}

	log.Info("✅ docker-compose.yml moved to /opt/hecate", zap.String("path", destPath))
	return nil
}
