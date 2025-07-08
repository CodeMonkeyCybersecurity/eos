// pkg/service_deployment/deployment.go
package service_deployment

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/system"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// ServiceDeployment represents a service deployment configuration
type ServiceDeployment struct {
	ServiceName    string            `json:"service_name"`
	DeploymentType string            `json:"deployment_type"`
	Image          string            `json:"image"`
	Config         map[string]string `json:"config"`
	Ports          []int             `json:"ports"`
	Environment    map[string]string `json:"environment"`
	Volumes        []VolumeConfig    `json:"volumes"`
}

// VolumeConfig represents a volume configuration
type VolumeConfig struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Mode        string `json:"mode"`
}

// DeploymentResult represents the result of a service deployment
type DeploymentResult struct {
	ServiceName string                 `json:"service_name"`
	Status      string                 `json:"status"`
	Message     string                 `json:"message"`
	Metadata    map[string]interface{} `json:"metadata"`
	Success     bool                   `json:"success"`
}

// GenerateServiceDeployment creates a service deployment configuration
// This follows the Assess → Intervene → Evaluate pattern
func GenerateServiceDeployment(rc *eos_io.RuntimeContext, serviceName, deploymentType, image, configFile string) (*ServiceDeployment, error) {
	logger := otelzap.Ctx(rc.Ctx)

	// ASSESS - Check prerequisites
	logger.Info("Assessing service deployment prerequisites",
		zap.String("service_name", serviceName),
		zap.String("deployment_type", deploymentType),
		zap.String("image", image),
		zap.String("config_file", configFile))

	if serviceName == "" {
		return nil, fmt.Errorf("service name is required")
	}

	if deploymentType == "" {
		deploymentType = "docker"
	}

	deployment := &ServiceDeployment{
		ServiceName:    serviceName,
		DeploymentType: deploymentType,
		Image:          image,
		Config:         make(map[string]string),
		Environment:    make(map[string]string),
		Volumes:        make([]VolumeConfig, 0),
	}

	// INTERVENE - Load configuration if provided
	if configFile != "" {
		logger.Info("Loading configuration from file", zap.String("config_file", configFile))

		if err := loadConfigFromFile(configFile, deployment); err != nil {
			return nil, fmt.Errorf("failed to load configuration: %w", err)
		}
	}

	// Set default configurations based on deployment type
	if err := setDefaultConfiguration(deployment); err != nil {
		return nil, fmt.Errorf("failed to set default configuration: %w", err)
	}

	// EVALUATE - Validate the deployment configuration
	logger.Info("Validating service deployment configuration")

	if err := validateDeployment(deployment); err != nil {
		return nil, fmt.Errorf("deployment validation failed: %w", err)
	}

	logger.Info("Service deployment configuration generated successfully",
		zap.String("service_name", deployment.ServiceName),
		zap.String("deployment_type", deployment.DeploymentType))

	return deployment, nil
}

// DisplayDeploymentResult shows the deployment result in a user-friendly format
func DisplayDeploymentResult(rc *eos_io.RuntimeContext, result *DeploymentResult) error {
	logger := otelzap.Ctx(rc.Ctx)

	logger.Info("Service deployment completed",
		zap.String("service_name", result.ServiceName),
		zap.String("status", result.Status),
		zap.Bool("success", result.Success))

	return nil
}

// loadConfigFromFile loads configuration from a JSON file
func loadConfigFromFile(configFile string, deployment *ServiceDeployment) error {
	if !filepath.IsAbs(configFile) {
		var err error
		configFile, err = filepath.Abs(configFile)
		if err != nil {
			return fmt.Errorf("failed to get absolute path: %w", err)
		}
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	// Parse configuration into deployment structure
	if ports, ok := config["ports"].([]interface{}); ok {
		for _, port := range ports {
			if p, ok := port.(float64); ok {
				deployment.Ports = append(deployment.Ports, int(p))
			}
		}
	}

	if env, ok := config["environment"].(map[string]interface{}); ok {
		for key, value := range env {
			if v, ok := value.(string); ok {
				deployment.Environment[key] = v
			}
		}
	}

	return nil
}

// setDefaultConfiguration sets default values based on deployment type
func setDefaultConfiguration(deployment *ServiceDeployment) error {
	switch deployment.DeploymentType {
	case "docker":
		if len(deployment.Ports) == 0 {
			deployment.Ports = []int{8080}
		}
		deployment.Config["restart_policy"] = "unless-stopped"
		deployment.Config["network_mode"] = "bridge"

	case "kubernetes":
		deployment.Config["replicas"] = "1"
		deployment.Config["strategy"] = "RollingUpdate"

	case "systemd":
		deployment.Config["type"] = "simple"
		deployment.Config["restart"] = "always"

	default:
		return fmt.Errorf("unsupported deployment type: %s", deployment.DeploymentType)
	}

	return nil
}

// validateDeployment validates the deployment configuration
func validateDeployment(deployment *ServiceDeployment) error {
	if deployment.ServiceName == "" {
		return fmt.Errorf("service name is required")
	}

	if deployment.DeploymentType == "docker" && deployment.Image == "" {
		return fmt.Errorf("image is required for docker deployment")
	}

	// Validate port ranges
	for _, port := range deployment.Ports {
		if port <= 0 || port > 65535 {
			return fmt.Errorf("invalid port number: %d", port)
		}
	}

	return nil
}

// ConvertToSystemDeployment converts ServiceDeployment to system.ServiceDeployment
func ConvertToSystemDeployment(deployment *ServiceDeployment) *system.ServiceDeployment {
	return &system.ServiceDeployment{
		Name:        deployment.ServiceName,
		Type:        deployment.DeploymentType,
		Environment: deployment.Environment,
		// Map other fields as needed
		Dependencies: []string{},
		HealthChecks: []system.HealthCheck{},
		Secrets:      make(map[string]string),
		Volumes:      []system.VolumeMount{},
		Networks:     []system.NetworkConfig{},
		Resources:    system.ResourceRequirements{},
		Scaling:      system.ScalingConfig{},
		UpdateStrategy: system.UpdateStrategy{},
	}
}

// ConvertFromSystemDeploymentResult converts system.DeploymentResult to service_deployment.DeploymentResult
func ConvertFromSystemDeploymentResult(systemResult *system.DeploymentResult) *DeploymentResult {
	return &DeploymentResult{
		ServiceName: systemResult.ServiceName,
		Status:      systemResult.Type,
		Message:     fmt.Sprintf("Deployment %s", func() string { if systemResult.Success { return "successful" } else { return "failed" } }()),
		Metadata: map[string]interface{}{
			"job_id":               systemResult.JobID,
			"allocations_created":  systemResult.AllocationsCreated,
			"health_status":        systemResult.HealthStatus,
			"endpoints":            systemResult.Endpoints,
			"duration":             systemResult.Duration,
			"errors":               systemResult.Errors,
			"rollback":             systemResult.Rollback,
		},
		Success: systemResult.Success,
	}
}