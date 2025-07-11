package consul

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/eos_io"
	"github.com/uptrace/opentelemetry-go-extra/otelzap"
	"go.uber.org/zap"
)

// GenerateClusterVariables generates Terraform variables file for Consul cluster
// Migrated from cmd/create/consul_terraform.go generateConsulClusterVariables
func GenerateClusterVariables(rc *eos_io.RuntimeContext, outputDir string, data *TemplateData) error {
	log := otelzap.Ctx(rc.Ctx)
	
	// ASSESS - Validate input parameters
	log.Info("Assessing Terraform variables generation requirements",
		zap.String("output_dir", outputDir),
		zap.String("cluster_name", data.ClusterName))
	
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	
	// INTERVENE - Generate variables file content
	log.Info("Generating Terraform variables file")
	
	variables := fmt.Sprintf(`
variable "vault_addr" {
  description = "Vault server address"
  type        = string
  default     = "%s"
}

variable "vault_token" {
  description = "Vault authentication token"
  type        = string
  sensitive   = true
}

variable "consul_datacenter" {
  description = "Consul datacenter name"
  type        = string
  default     = "%s"
}

variable "cluster_name" {
  description = "Consul cluster name"
  type        = string
  default     = "%s"
}

variable "server_count" {
  description = "Number of Consul servers"
  type        = number
  default     = %d
}

variable "client_count" {
  description = "Number of Consul clients"
  type        = number
  default     = %d
}

variable "server_type" {
  description = "Hetzner server type"
  type        = string
  default     = "%s"
}

variable "location" {
  description = "Hetzner location"
  type        = string
  default     = "%s"
}

variable "ssh_key_name" {
  description = "SSH key name in Hetzner Cloud"
  type        = string
  default     = "%s"
}
`, data.VaultAddr, data.ConsulDatacenter, data.ClusterName, data.ServerCount, data.ClientCount, data.ServerType, data.Location, data.SSHKeyName)

	variablesPath := filepath.Join(outputDir, "variables.tf")
	if err := os.WriteFile(variablesPath, []byte(variables), 0644); err != nil {
		return fmt.Errorf("failed to write variables file: %w", err)
	}
	
	// EVALUATE - Verify file was written correctly
	log.Info("Evaluating Terraform variables file generation")
	
	info, err := os.Stat(variablesPath)
	if err != nil {
		return fmt.Errorf("failed to verify variables file: %w", err)
	}
	
	log.Info("Terraform variables file generated successfully",
		zap.String("path", variablesPath),
		zap.Int64("size", info.Size()),
		zap.String("datacenter", data.ConsulDatacenter),
		zap.String("cluster_name", data.ClusterName))
	
	return nil
}