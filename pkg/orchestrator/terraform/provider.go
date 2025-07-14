// pkg/orchestrator/terraform/provider.go
package terraform

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/execute"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/orchestrator"
	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// Provider manages Terraform operations
type Provider struct {
	rc       *eos_io.RuntimeContext
	workDir  string
	vars     map[string]interface{}
	config   Config
}

// Config holds Terraform provider configuration
type Config struct {
	WorkspaceDir   string
	StateBackend   string
	BackendConfig  map[string]string
	AutoApprove    bool
	Parallelism    int
	PluginCacheDir string
}

// NewProvider creates a new Terraform provider
func NewProvider(rc *eos_io.RuntimeContext, config Config) *Provider {
	return &Provider{
		rc:      rc,
		workDir: config.WorkspaceDir,
		vars:    make(map[string]interface{}),
		config:  config,
	}
}

// GenerateConfig generates Terraform configuration for a component
func (p *Provider) GenerateConfig(component orchestrator.Component) (string, error) {
	switch component.Name {
	case "consul":
		return p.generateConsulConfig(component)
	case "vault":
		return p.generateVaultConfig(component)
	case "nomad":
		return p.generateNomadConfig(component)
	default:
		return "", fmt.Errorf("unsupported component: %s", component.Name)
	}
}

// generateConsulConfig generates Terraform config for Consul as a Nomad job
func (p *Provider) generateConsulConfig(component orchestrator.Component) (string, error) {
	config, ok := component.Config.(orchestrator.ConsulConfig)
	if !ok {
		return "", fmt.Errorf("invalid config type for consul")
	}

	tmpl := `terraform {
  required_providers {
    nomad = {
      source  = "hashicorp/nomad"
      version = "~> 2.0"
    }
  }
  
  backend "consul" {
    address = "localhost:{{ .ConsulPort }}"
    path    = "terraform/{{ .ComponentName }}/state"
    lock    = true
  }
}

provider "nomad" {
  address = var.nomad_address
}

variable "nomad_address" {
  description = "Nomad server address"
  type        = string
  default     = "http://localhost:4646"
}

variable "datacenter" {
  description = "Nomad datacenter"
  type        = string
  default     = "{{ .Datacenter }}"
}

variable "consul_version" {
  description = "Consul version to deploy"
  type        = string
  default     = "{{ .Version }}"
}

resource "nomad_job" "consul" {
  jobspec = templatefile("${path.module}/jobs/consul.nomad.hcl", {
    datacenter       = var.datacenter
    consul_version   = var.consul_version
    http_port        = {{ .HTTPPort }}
    dns_port         = {{ .DNSPort }}
    server_mode      = {{ .ServerMode }}
    bootstrap_expect = {{ .BootstrapExpect }}
    ui_enabled       = {{ .UIEnabled }}
    encryption_key   = "{{ .EncryptionKey }}"
    tls_enabled      = {{ .TLSEnabled }}
  })
  
  purge_on_destroy = true
}

# Create Consul service registration for the Consul servers themselves
resource "nomad_job" "consul_service_registration" {
  depends_on = [nomad_job.consul]
  
  jobspec = templatefile("${path.module}/jobs/consul-service-registration.nomad.hcl", {
    datacenter = var.datacenter
    http_port  = {{ .HTTPPort }}
  })
}

output "consul_http_addr" {
  value = "http://consul.service.consul:{{ .HTTPPort }}"
}

output "consul_dns_addr" {
  value = "consul.service.consul:{{ .DNSPort }}"
}

output "job_id" {
  value = nomad_job.consul.id
}
`

	// Create template data
	data := map[string]interface{}{
		"ComponentName":   component.Name,
		"Datacenter":      config.Datacenter,
		"Version":         component.Version,
		"HTTPPort":        shared.PortConsul,
		"DNSPort":         config.Ports.DNS,
		"ServerMode":      config.ServerMode,
		"BootstrapExpect": config.BootstrapExpect,
		"UIEnabled":       config.UIEnabled,
		"EncryptionKey":   config.EncryptionKey,
		"TLSEnabled":      config.TLSEnabled,
		"ConsulPort":      shared.PortConsul,
	}

	return p.renderTemplate(tmpl, data)
}

// generateVaultConfig generates Terraform config for Vault
func (p *Provider) generateVaultConfig(component orchestrator.Component) (string, error) {
	// TODO: Implement Vault Terraform generation
	return "", fmt.Errorf("vault terraform generation not implemented")
}

// generateNomadConfig generates Terraform config for Nomad
func (p *Provider) generateNomadConfig(component orchestrator.Component) (string, error) {
	// TODO: Implement Nomad Terraform generation
	return "", fmt.Errorf("nomad terraform generation not implemented")
}

// renderTemplate renders a template with the given data
func (p *Provider) renderTemplate(tmplStr string, data interface{}) (string, error) {
	tmpl, err := template.New("terraform").Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}

	var buf strings.Builder
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// Apply applies Terraform configuration
func (p *Provider) Apply(ctx context.Context, component orchestrator.Component) error {
	logger := otelzap.Ctx(p.rc.Ctx)
	
	// Create component directory
	componentDir := filepath.Join(p.workDir, component.Name)
	if err := os.MkdirAll(componentDir, 0755); err != nil {
		return fmt.Errorf("failed to create component directory: %w", err)
	}

	// Generate and save main.tf
	config, err := p.GenerateConfig(component)
	if err != nil {
		return fmt.Errorf("failed to generate terraform config: %w", err)
	}

	mainTfPath := filepath.Join(componentDir, "main.tf")
	if err := os.WriteFile(mainTfPath, []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write main.tf: %w", err)
	}

	// Generate and save Nomad job file
	jobSpec, err := p.generateNomadJobSpec(component)
	if err != nil {
		return fmt.Errorf("failed to generate nomad job spec: %w", err)
	}

	jobsDir := filepath.Join(componentDir, "jobs")
	if err := os.MkdirAll(jobsDir, 0755); err != nil {
		return fmt.Errorf("failed to create jobs directory: %w", err)
	}

	jobPath := filepath.Join(jobsDir, fmt.Sprintf("%s.nomad.hcl", component.Name))
	if err := os.WriteFile(jobPath, []byte(jobSpec), 0644); err != nil {
		return fmt.Errorf("failed to write nomad job file: %w", err)
	}

	// Initialize Terraform
	logger.Info("Initializing Terraform")
	initCmd := execute.Options{
		Command:    "terraform",
		Args:       []string{"init", "-upgrade"},
		Dir: componentDir,
		Capture:    true,
	}

	output, err := execute.Run(p.rc.Ctx, initCmd)
	if err != nil {
		logger.Error("Terraform init failed",
			zap.Error(err),
			zap.String("output", output))
		return fmt.Errorf("terraform init failed: %w", err)
	}

	// Plan
	logger.Info("Planning Terraform changes")
	planCmd := execute.Options{
		Command:    "terraform",
		Args:       []string{"plan", "-out=tfplan"},
		Dir: componentDir,
		Capture:    true,
	}

	output, err = execute.Run(p.rc.Ctx, planCmd)
	if err != nil {
		logger.Error("Terraform plan failed",
			zap.Error(err),
			zap.String("output", output))
		return fmt.Errorf("terraform plan failed: %w", err)
	}

	// Apply
	logger.Info("Applying Terraform changes")
	applyArgs := []string{"apply"}
	if p.config.AutoApprove {
		applyArgs = append(applyArgs, "-auto-approve")
	}
	applyArgs = append(applyArgs, "tfplan")

	applyCmd := execute.Options{
		Command:    "terraform",
		Args:       applyArgs,
		Dir: componentDir,
		Capture:    true,
	}

	_, err = execute.Run(p.rc.Ctx, applyCmd)
	if err != nil {
		logger.Error("Terraform apply failed",
			zap.Error(err))
		return fmt.Errorf("terraform apply failed: %w", err)
	}

	logger.Info("Terraform applied successfully",
		zap.String("component", component.Name))

	return nil
}

// generateNomadJobSpec generates a Nomad job specification
func (p *Provider) generateNomadJobSpec(component orchestrator.Component) (string, error) {
	switch component.Name {
	case "consul":
		return p.generateConsulNomadJob(component)
	default:
		return "", fmt.Errorf("unsupported component for nomad job: %s", component.Name)
	}
}

// generateConsulNomadJob generates a Nomad job spec for Consul
func (p *Provider) generateConsulNomadJob(component orchestrator.Component) (string, error) {
	config, ok := component.Config.(orchestrator.ConsulConfig)
	if !ok {
		return "", fmt.Errorf("invalid config type for consul")
	}

	tmpl := `job "consul" {
  datacenters = ["{{ .Datacenter }}"]
  type        = "service"
  
  update {
    max_parallel      = 1
    health_check      = "checks"
    min_healthy_time  = "10s"
    healthy_deadline  = "5m"
    progress_deadline = "10m"
    stagger           = "30s"
  }

  group "consul-servers" {
    count = {{ .BootstrapExpect }}
    
    network {
      port "http" {
        static = {{ .HTTPPort }}
      }
      port "serf_lan" {
        static = 8301
      }
      port "serf_wan" {
        static = 8302
      }
      port "rpc" {
        static = 8300
      }
      port "dns" {
        static = {{ .DNSPort }}
      }
    }

    task "consul" {
      driver = "docker"
      
      config {
        image        = "consul:{{ .Version }}"
        network_mode = "host"
        volumes = [
          "local/consul.hcl:/consul/config/consul.hcl",
          "consul-data:/consul/data",
        ]
        args = [
          "agent",
          "-config-dir=/consul/config",
        ]
      }
      
      template {
        data = <<EOH
datacenter = "{{ .Datacenter }}"
data_dir = "/consul/data"
log_level = "INFO"
node_name = "consul-${NOMAD_ALLOC_INDEX}"
server = true
bootstrap_expect = {{ .BootstrapExpect }}
ui_config {
  enabled = {{ .UIEnabled }}
}
connect {
  enabled = true
}
ports {
  http = {{ .HTTPPort }}
  dns = {{ .DNSPort }}
}
client_addr = "0.0.0.0"
{{ if .EncryptionKey }}
encrypt = "{{ .EncryptionKey }}"
{{ end }}
{{ if .TLSEnabled }}
tls {
  defaults {
    verify_incoming = true
    verify_outgoing = true
  }
  internal_rpc {
    verify_server_hostname = true
  }
}
{{ end }}
EOH
        destination = "local/consul.hcl"
      }
      
      resources {
        cpu    = 500
        memory = 256
      }
      
      service {
        name = "consul"
        port = "http"
        
        check {
          type     = "http"
          path     = "/v1/status/leader"
          interval = "10s"
          timeout  = "2s"
        }
      }
    }
  }
}
`

	// Create template data
	data := map[string]interface{}{
		"Datacenter":      config.Datacenter,
		"Version":         component.Version,
		"HTTPPort":        shared.PortConsul,
		"DNSPort":         config.Ports.DNS,
		"BootstrapExpect": config.BootstrapExpect,
		"UIEnabled":       config.UIEnabled,
		"EncryptionKey":   config.EncryptionKey,
		"TLSEnabled":      config.TLSEnabled,
	}

	return p.renderTemplate(tmpl, data)
}

// Destroy destroys Terraform-managed resources
func (p *Provider) Destroy(ctx context.Context, component orchestrator.Component) error {
	logger := otelzap.Ctx(p.rc.Ctx)
	
	componentDir := filepath.Join(p.workDir, component.Name)
	
	destroyCmd := execute.Options{
		Command:    "terraform",
		Args:       []string{"destroy", "-auto-approve"},
		Dir: componentDir,
		Capture:    true,
	}

	output, err := execute.Run(p.rc.Ctx, destroyCmd)
	if err != nil {
		logger.Error("Terraform destroy failed",
			zap.Error(err),
			zap.String("output", output))
		return fmt.Errorf("terraform destroy failed: %w", err)
	}

	logger.Info("Terraform resources destroyed",
		zap.String("component", component.Name))

	return nil
}

// GetOutputs retrieves Terraform outputs
func (p *Provider) GetOutputs(ctx context.Context, component orchestrator.Component) (map[string]string, error) {
	componentDir := filepath.Join(p.workDir, component.Name)
	
	outputCmd := execute.Options{
		Command:    "terraform",
		Args:       []string{"output", "-json"},
		Dir: componentDir,
		Capture:    true,
	}

	output, err := execute.Run(p.rc.Ctx, outputCmd)
	if err != nil {
		return nil, fmt.Errorf("failed to get terraform outputs: %w", err)
	}

	// Parse JSON output
	outputs := make(map[string]string)
	// TODO: Implement JSON parsing of Terraform outputs
	_ = output // Suppress unused variable warning
	
	return outputs, nil
}

// Preview generates and returns Terraform configuration without applying
func (p *Provider) Preview(component orchestrator.Component) (string, error) {
	mainConfig, err := p.GenerateConfig(component)
	if err != nil {
		return "", fmt.Errorf("failed to generate main config: %w", err)
	}

	jobSpec, err := p.generateNomadJobSpec(component)
	if err != nil {
		return "", fmt.Errorf("failed to generate job spec: %w", err)
	}

	preview := fmt.Sprintf("=== main.tf ===\n%s\n\n=== jobs/%s.nomad.hcl ===\n%s",
		mainConfig, component.Name, jobSpec)

	return preview, nil
}