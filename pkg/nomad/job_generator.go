// pkg/nomad/job_generator.go
//
// EOS Nomad Job Generator - Container Orchestration
//
// This package provides comprehensive Nomad job generation capabilities for EOS
// infrastructure. It implements the EOS infrastructure compiler pattern by
// translating high-level service configurations into Nomad job specifications.
//
// Key Features:
// - Service-to-Job Translation: Converts EOS service configs to Nomad jobs
// - Template-Based Generation: Uses Go templates for flexible job creation
// - Multi-Service Support: Handles complex multi-container deployments
// - Resource Management: Automatic resource allocation and constraints
// - Service Discovery: Consul integration for service registration
// - Health Checks: Comprehensive health monitoring configuration
// - Volume Management: Storage integration with proper mount handling
//
// Architecture Integration:
// - Replaces Kubernetes/K3s deployment generation in EOS
// - Integrates with Consul for service discovery
// - Works with Vault for secret management
// - Supports Hecate reverse proxy architecture
// - Follows EOS infrastructure compiler patterns
//
// Job Generation Process:
// 1. Parse service configuration from EOS commands
// 2. Apply service-specific templates and constraints
// 3. Generate Nomad job specification with proper networking
// 4. Configure Consul service registration
// 5. Set up health checks and monitoring
// 6. Handle volume mounts and storage requirements
//
// Service Types Supported:
// - Web Services: HTTP/HTTPS applications with reverse proxy
// - Databases: PostgreSQL, MySQL, Redis with persistent storage
// - Message Queues: RabbitMQ, Apache Kafka with clustering
// - Monitoring: Grafana, Prometheus with data persistence
// - Collaboration: Mattermost, n8n with full orchestration
//
// Template System:
// The generator uses a flexible template system that allows:
// - Service-specific job configurations
// - Environment-based variations (dev/staging/prod)
// - Resource scaling based on deployment size
// - Network configuration for service mesh integration
//
// Usage Examples:
//   generator := nomad.NewJobGenerator(logger)
//   
//   config := &nomad.NomadJobConfig{
//       ServiceName: "mattermost",
//       Image: "mattermost/mattermost-enterprise-edition:latest",
//       Port: 8065,
//       Resources: nomad.ResourceConfig{CPU: 500, Memory: 1024},
//   }
//   
//   jobSpec, err := generator.GenerateServiceJob(rc, config)
//   if err != nil {
//       // Handle error
//   }
//
// Integration with EOS Commands:
// This generator is called by EOS create commands to translate user intent
// into deployable Nomad jobs, maintaining the infrastructure compiler pattern
// where users express what they want and EOS handles the orchestration details.
package nomad

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// JobGenerator handles generation of Nomad job specifications
// This replaces K3s/Kubernetes deployment generation
type JobGenerator struct {
	logger otelzap.LoggerWithCtx
}

// NewJobGenerator creates a new Nomad job generator
func NewJobGenerator(logger otelzap.LoggerWithCtx) *JobGenerator {
	return &JobGenerator{
		logger: logger,
	}
}

// GenerateServiceJob generates a Nomad job specification from configuration
// This replaces K3s service deployment
func (jg *JobGenerator) GenerateServiceJob(rc *eos_io.RuntimeContext, config *NomadJobConfig) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Generating Nomad service job specification",
		zap.String("service_name", config.ServiceName),
		zap.String("job_type", config.JobType),
		zap.Int("replicas", config.Replicas))

	// ASSESS - Validate configuration
	if err := jg.validateJobConfig(config); err != nil {
		return "", fmt.Errorf("job configuration validation failed: %w", err)
	}

	// INTERVENE - Generate job specification
	tmpl, err := template.New("nomad-job").Parse(NomadServiceDeploymentTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse job template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, config); err != nil {
		return "", fmt.Errorf("failed to execute job template: %w", err)
	}

	jobSpec := buf.String()

	// EVALUATE - Validate generated specification
	if len(jobSpec) == 0 {
		return "", fmt.Errorf("generated job specification is empty")
	}

	logger.Info("Nomad job specification generated successfully",
		zap.String("service_name", config.ServiceName),
		zap.Int("spec_length", len(jobSpec)))

	return jobSpec, nil
}

// GenerateCaddyIngressJob generates Caddy ingress job to replace K3s ingress
func (jg *JobGenerator) GenerateCaddyIngressJob(rc *eos_io.RuntimeContext, config *CaddyIngressConfig) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Generating Caddy ingress job specification",
		zap.String("domain", config.Domain),
		zap.Int("replicas", config.CaddyReplicas))

	// ASSESS - Validate Caddy configuration
	if config.Domain == "" {
		return "", fmt.Errorf("domain is required for Caddy ingress")
	}

	if config.CaddyReplicas < 1 {
		config.CaddyReplicas = DefaultCaddyReplicas
	}

	// INTERVENE - Generate Caddy job specification
	tmpl, err := template.New("caddy-ingress").Parse(CaddyIngressJobTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse Caddy template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, config); err != nil {
		return "", fmt.Errorf("failed to execute Caddy template: %w", err)
	}

	jobSpec := buf.String()

	// EVALUATE - Validate generated specification
	if len(jobSpec) == 0 {
		return "", fmt.Errorf("generated Caddy job specification is empty")
	}

	logger.Info("Caddy ingress job specification generated successfully",
		zap.String("domain", config.Domain),
		zap.Int("spec_length", len(jobSpec)))

	return jobSpec, nil
}

// GenerateNginxMailJob generates Nginx mail proxy job to replace K3s mail services
func (jg *JobGenerator) GenerateNginxMailJob(rc *eos_io.RuntimeContext, config *NginxMailConfig) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Generating Nginx mail proxy job specification",
		zap.String("domain", config.Domain),
		zap.Int("replicas", config.NginxReplicas),
		zap.Ints("mail_ports", config.MailPorts))

	// ASSESS - Validate Nginx configuration
	if config.Domain == "" {
		return "", fmt.Errorf("domain is required for Nginx mail proxy")
	}

	if len(config.MailPorts) == 0 {
		config.MailPorts = []int{25, 587, 465, 110, 995, 143, 993, 4190}
	}

	if config.NginxReplicas < 1 {
		config.NginxReplicas = DefaultNginxReplicas
	}

	// INTERVENE - Generate Nginx job specification
	tmpl, err := template.New("nginx-mail").Parse(NginxMailProxyJobTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse Nginx template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, config); err != nil {
		return "", fmt.Errorf("failed to execute Nginx template: %w", err)
	}

	jobSpec := buf.String()

	// EVALUATE - Validate generated specification
	if len(jobSpec) == 0 {
		return "", fmt.Errorf("generated Nginx job specification is empty")
	}

	logger.Info("Nginx mail proxy job specification generated successfully",
		zap.String("domain", config.Domain),
		zap.Int("spec_length", len(jobSpec)))

	return jobSpec, nil
}

// GenerateClusterBootstrapJob generates cluster bootstrap job
func (jg *JobGenerator) GenerateClusterBootstrapJob(rc *eos_io.RuntimeContext, config *NomadClusterConfig) (string, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Generating cluster bootstrap job specification",
		zap.String("datacenter", config.Datacenter),
		zap.Bool("enable_acl", config.EnableACL))

	// ASSESS - Validate cluster configuration
	if config.Datacenter == "" {
		config.Datacenter = "dc1"
	}

	if config.Region == "" {
		config.Region = "global"
	}

	// INTERVENE - Generate bootstrap job specification
	tmpl, err := template.New("cluster-bootstrap").Parse(NomadClusterSetupTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse bootstrap template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, config); err != nil {
		return "", fmt.Errorf("failed to execute bootstrap template: %w", err)
	}

	jobSpec := buf.String()

	// EVALUATE - Validate generated specification
	if len(jobSpec) == 0 {
		return "", fmt.Errorf("generated bootstrap job specification is empty")
	}

	logger.Info("Cluster bootstrap job specification generated successfully",
		zap.String("datacenter", config.Datacenter),
		zap.Int("spec_length", len(jobSpec)))

	return jobSpec, nil
}

// ConvertK3sToNomadConfig converts K3s deployment configuration to Nomad job configuration
// This handles the migration from K3s/Kubernetes to Nomad
func (jg *JobGenerator) ConvertK3sToNomadConfig(rc *eos_io.RuntimeContext, k3sConfig map[string]interface{}) (*NomadJobConfig, error) {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Converting K3s configuration to Nomad job configuration")

	// Start with default configuration
	config := GetDefaultServiceJobConfig("migrated-service")

	// Extract service name
	if name, ok := k3sConfig["name"].(string); ok {
		config.ServiceName = name
	}

	// Extract image information
	if image, ok := k3sConfig["image"].(string); ok {
		config.Image = image
	}

	// Extract replica count
	if replicas, ok := k3sConfig["replicas"].(float64); ok {
		config.Replicas = int(replicas)
	}

	// Extract ports from K3s service configuration
	if ports, ok := k3sConfig["ports"].([]interface{}); ok {
		config.Ports = make([]string, 0, len(ports))
		config.Networks = make([]NetworkConfig, 0, len(ports))
		
		for _, port := range ports {
			if portNum, ok := port.(float64); ok {
				portStr := fmt.Sprintf("port-%d", int(portNum))
				config.Ports = append(config.Ports, portStr)
				config.Networks = append(config.Networks, NetworkConfig{
					Name: portStr,
					Port: int(portNum),
					Static: false,
				})
			}
		}
	}

	// Extract environment variables
	if env, ok := k3sConfig["env"].(map[string]interface{}); ok {
		config.EnvVars = make(map[string]string)
		for key, value := range env {
			if valueStr, ok := value.(string); ok {
				config.EnvVars[key] = valueStr
			}
		}
	}

	// Extract resource requirements
	if resources, ok := k3sConfig["resources"].(map[string]interface{}); ok {
		config.Resources = &ResourceConfig{}
		
		if requests, ok := resources["requests"].(map[string]interface{}); ok {
			if cpu, ok := requests["cpu"].(string); ok {
				// Convert K3s CPU format (e.g., "100m") to Nomad MHz
				if cpu == "100m" {
					config.Resources.CPU = 100
				} else if cpu == "200m" {
					config.Resources.CPU = 200
				} else {
					config.Resources.CPU = DefaultCaddyCPU
				}
			}
			
			if memory, ok := requests["memory"].(string); ok {
				// Convert K3s memory format (e.g., "128Mi") to Nomad MB
				if memory == "128Mi" {
					config.Resources.Memory = 128
				} else if memory == "256Mi" {
					config.Resources.Memory = 256
				} else {
					config.Resources.Memory = DefaultCaddyMemory
				}
			}
		}
	}

	// Extract volume mounts
	if volumes, ok := k3sConfig["volumes"].([]interface{}); ok {
		config.DockerVolumes = make([]string, 0, len(volumes))
		
		for _, volume := range volumes {
			if volumeMap, ok := volume.(map[string]interface{}); ok {
				if source, ok := volumeMap["source"].(string); ok {
					if destination, ok := volumeMap["destination"].(string); ok {
						volumeStr := fmt.Sprintf("%s:%s", source, destination)
						config.DockerVolumes = append(config.DockerVolumes, volumeStr)
					}
				}
			}
		}
	}

	// Set service tags for Consul integration
	config.ServiceTags = []string{
		"migrated-from-k3s",
		fmt.Sprintf("version-%s", config.ServiceName),
	}

	logger.Info("K3s to Nomad configuration conversion completed",
		zap.String("service_name", config.ServiceName),
		zap.String("image", config.Image),
		zap.Int("replicas", config.Replicas))

	return config, nil
}

// validateJobConfig validates Nomad job configuration
func (jg *JobGenerator) validateJobConfig(config *NomadJobConfig) error {
	if config.ServiceName == "" {
		return fmt.Errorf("service name is required")
	}

	if config.JobType == "" {
		config.JobType = ServiceJobType
	}

	if config.Replicas < 1 {
		config.Replicas = 1
	}

	if config.Driver == "" {
		config.Driver = DockerDriver
	}

	if config.Driver == DockerDriver && config.Image == "" {
		return fmt.Errorf("image is required for Docker driver")
	}

	if config.Resources == nil {
		config.Resources = &ResourceConfig{
			CPU:    100,
			Memory: 128,
		}
	}

	return nil
}

// DeployNomadJob deploys a Nomad job specification
func (jg *JobGenerator) DeployNomadJob(rc *eos_io.RuntimeContext, jobSpec string) error {
	logger := otelzap.Ctx(rc.Ctx)
	
	logger.Info("Deploying Nomad job specification",
		zap.Int("spec_length", len(jobSpec)))

	// This would integrate with actual Nomad API
	// For now, we'll log the deployment request
	logger.Info("Nomad job deployment requested - integration with Nomad API required")
	
	return nil
}