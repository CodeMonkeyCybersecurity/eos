package container

import (
	"fmt"
	"os"
	"strconv"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/domain/sysinfo"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/templates"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

func DeployZabbix(rc *eos_io.RuntimeContext) error {
	logger := otelzap.Ctx(rc.Ctx)
	logger.Info(" Starting Zabbix monitoring stack deployment")

	// Define configuration variables
	timeZone := "auto"
	zabbixWebPort := strconv.Itoa(shared.PortZabbix)
	zabbixWebSSLPort := strconv.Itoa(shared.PortZabbix + 1) // Next port for SSL
	zabbixServerPort := "10051"                             // Standard Zabbix server port
	zabbixAgentPort := "10050"                              // Standard Zabbix agent port
	postgresPassword := "zabbix_secure_pwd"

	// Ensure Docker is installed and running (install if needed)
	logger.Info(" Checking Docker dependencies")
	if err := EnsureDockerInstalled(rc); err != nil {
		return fmt.Errorf("docker dependency check failed: %w", err)
	}

	// Ensure Docker Compose is installed
	if err := CheckIfDockerComposeInstalled(rc); err != nil {
		return fmt.Errorf("docker compose check failed: %w", err)
	}

	// Create target directory
	logger.Info(" Creating Zabbix deployment directory", zap.String("path", shared.ZabbixDir))
	if err := os.MkdirAll(shared.ZabbixDir, shared.DirPermStandard); err != nil {
		return fmt.Errorf("failed to create %s: %w", shared.ZabbixDir, err)
	}

	// Auto-detect timezone if not explicitly set
	effectiveTimeZone := timeZone
	if timeZone == "auto" || timeZone == "" {
		if detectedTZ, err := sysinfo.DetectHostTimeZone(rc); err != nil {
			logger.Warn(" Failed to detect host timezone, using UTC", zap.Error(err))
			effectiveTimeZone = "UTC"
		} else {
			effectiveTimeZone = detectedTZ
			logger.Info(" Auto-detected host timezone", zap.String("timezone", effectiveTimeZone))
		}
	}

	// Generate Docker Compose configuration from template
	logger.Info(" Generating Zabbix Docker Compose configuration",
		zap.String("timezone", effectiveTimeZone))
	templateVars := map[string]string{
		"ZabbixWebPort":    zabbixWebPort,
		"ZabbixWebSSLPort": zabbixWebSSLPort,
		"ZabbixServerPort": zabbixServerPort,
		"ZabbixAgentPort":  zabbixAgentPort,
		"PostgresPassword": postgresPassword,
		"TimeZone":         effectiveTimeZone,
	}

	if err := generateZabbixComposeFile(shared.ZabbixComposeYML, templateVars); err != nil {
		return fmt.Errorf("failed to generate compose file: %w", err)
	}

	logger.Info(" Docker Compose file generated successfully", zap.String("file", shared.ZabbixComposeYML))

	// Start the stack
	logger.Info(" Starting Zabbix monitoring stack with Docker Compose")
	if err := ComposeUp(rc, shared.ZabbixComposeYML); err != nil {
		return fmt.Errorf("failed to start Zabbix stack: %w", err)
	}

	logger.Info(" Zabbix monitoring stack started successfully")
	return nil
}

// generateZabbixComposeFile creates the Docker Compose file from template
func generateZabbixComposeFile(filePath string, vars map[string]string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("create compose file: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			fmt.Printf("Warning: Failed to close file: %v\n", err)
		}
	}()

	if err := templates.ZabbixComposeTemplate.Execute(file, vars); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	return nil
}
