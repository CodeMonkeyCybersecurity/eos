package inspect

import (
	"fmt"
	"os"
	"strings"
)

// generateMainTf creates the main Terraform configuration
func (c *TerraformConfig) generateMainTf() error {
	content := fmt.Sprintf(`terraform {
  required_version = ">= 1.6"
  
  backend "s3" {
    bucket         = "eos-terraform-state"
    key            = "%s/${terraform.workspace}.tfstate"
    region         = "ap-southeast-2"
    dynamodb_table = "terraform-locks"
    encrypt        = true
  }
  
  required_providers {`, c.Infrastructure.Hostname)

	// Add providers based on what resources we have
	if c.Infrastructure.Docker != nil && (len(c.Infrastructure.Docker.Containers) > 0 || len(c.Infrastructure.Docker.Networks) > 0 || len(c.Infrastructure.Docker.Volumes) > 0) {
		content += `
    docker = {
      source  = "kreuzwerker/docker"
      version = "3.0.2"
    }`
	}

	if c.Infrastructure.Hetzner != nil && (len(c.Infrastructure.Hetzner.Servers) > 0 || len(c.Infrastructure.Hetzner.Networks) > 0) {
		content += `
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "1.45.0"
    }`
	}

	if c.Infrastructure.KVM != nil && len(c.Infrastructure.KVM.VMs) > 0 {
		content += `
    libvirt = {
      source  = "dmacvicar/libvirt"
      version = "0.7.6"
    }`
	}

	content += `
  }
}

locals {
  common_labels = {
    environment  = var.environment
    managed_by   = "terraform"
    generated_by = "eos-inspector"
    hostname     = "` + c.Infrastructure.Hostname + `"
  }
}
`

	return os.WriteFile(c.BaseDir+"/main.tf", []byte(content), 0644)
}

// generateVariablesTf creates the variables configuration
func (c *TerraformConfig) generateVariablesTf() error {
	content := `variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  default     = "dev"
  
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "enable_monitoring" {
  description = "Enable monitoring and logging for containers"
  type        = bool
  default     = true
}

variable "container_ports" {
  description = "Port mappings for containers"
  type = map(object({
    internal = number
    external = number
    protocol = string
  }))
  default = {}
  
  validation {
    condition = alltrue([
      for k, v in var.container_ports : 
      v.external >= 1024 && v.external <= 65535
    ])
    error_message = "External ports must be between 1024 and 65535."
  }
}

variable "volumes" {
  description = "Volume configurations"
  type = map(object({
    driver = string
    labels = map(string)
  }))
  default = {}
  sensitive = false
}
`

	return os.WriteFile(c.BaseDir+"/variables.tf", []byte(content), 0644)
}

// generateOutputsTf creates the outputs configuration
func (c *TerraformConfig) generateOutputsTf() error {
	content := `output "infrastructure_summary" {
  description = "Summary of managed infrastructure"
  value = {
    hostname    = "` + c.Infrastructure.Hostname + `"
    environment = var.environment
  }
}
`

	if c.Infrastructure.Docker != nil && hasWazuhVolumes(c.Infrastructure.Docker) {
		content += `
output "wazuh_volume_names" {
  description = "Names of created Wazuh volumes"
  value       = module.wazuh_volumes.volume_names
}
`
	}

	return os.WriteFile(c.BaseDir+"/outputs.tf", []byte(content), 0644)
}

// generateDockerResources creates Docker-specific Terraform files
func (c *TerraformConfig) generateDockerResources() error {
	c.Logger.Info(" Generating modular Docker resources")

	// Generate container configuration
	if err := c.generateDockerContainers(); err != nil {
		return err
	}

	// Generate network configuration
	if err := c.generateDockerNetworks(); err != nil {
		return err
	}

	// Generate volume configuration
	if err := c.generateDockerVolumes(); err != nil {
		return err
	}

	return nil
}

// generateDockerContainers creates container-specific configuration
func (c *TerraformConfig) generateDockerContainers() error {
	var tf strings.Builder

	tf.WriteString(`# Docker Containers
# Generated from infrastructure inspection

`)

	for _, container := range c.Infrastructure.Docker.Containers {
		if container.State != "running" {
			continue
		}

		resourceName := sanitizeTerraformName(container.Name)
		tf.WriteString(fmt.Sprintf(`resource "docker_container" "%s" {
  name    = "${var.environment}_%s"
  image   = "%s"
  restart = "always"
  
  labels = local.common_labels
`, resourceName, container.Name, container.Image))

		// Add dynamic port mapping
		if len(container.Ports) > 0 {
			tf.WriteString(`
  dynamic "ports" {
    for_each = { for k, v in var.container_ports : k => v if k == "` + container.Name + `" }
    content {
      internal = ports.value.internal
      external = ports.value.external
      protocol = ports.value.protocol
    }
  }
`)
		}

		// Add volumes as mounts for better practices
		if len(container.Volumes) > 0 {
			for _, volume := range container.Volumes {
				parts := strings.Split(volume, ":")
				if len(parts) >= 2 {
					tf.WriteString(fmt.Sprintf(`  mounts {
    target = "%s"
    source = "%s"
    type   = "bind"
    read_only = %t
  }
`, parts[1], parts[0], len(parts) > 2 && parts[2] == "ro"))
				}
			}
		}

		// Add network connections
		if len(container.Networks) > 0 {
			for _, network := range container.Networks {
				if network != "bridge" && network != "host" && network != "none" {
					networkResourceName := sanitizeTerraformName(network)
					tf.WriteString(fmt.Sprintf(`  networks_advanced {
    name = docker_network.%s.name
  }
`, networkResourceName))
				}
			}
		}

		tf.WriteString("}\n\n")
	}

	return os.WriteFile(c.BaseDir+"/docker/containers.tf", []byte(tf.String()), 0644)
}

// generateDockerNetworks creates network-specific configuration
func (c *TerraformConfig) generateDockerNetworks() error {
	var tf strings.Builder

	tf.WriteString(`# Docker Networks
# Generated from infrastructure inspection

`)

	for _, network := range c.Infrastructure.Docker.Networks {
		if network.Name == "bridge" || network.Name == "host" || network.Name == "none" {
			continue
		}

		resourceName := sanitizeTerraformName(network.Name)
		tf.WriteString(fmt.Sprintf(`resource "docker_network" "%s" {
  name   = "%s"
  driver = "%s"
  
  labels = merge(local.common_labels, {
    network_scope = "%s"
  })
}

`, resourceName, network.Name, network.Driver, network.Scope))
	}

	return os.WriteFile(c.BaseDir+"/docker/networks.tf", []byte(tf.String()), 0644)
}

// generateDockerVolumes creates volume-specific configuration (excluding Wazuh)
func (c *TerraformConfig) generateDockerVolumes() error {
	var tf strings.Builder

	tf.WriteString(`# Docker Volumes (Non-Wazuh)
# Generated from infrastructure inspection
# Note: Wazuh volumes are managed by the wazuh-volumes module

`)

	for _, volume := range c.Infrastructure.Docker.Volumes {
		// Skip Wazuh volumes as they're handled by the module
		if strings.Contains(volume.Name, "wazuh") {
			continue
		}

		resourceName := sanitizeTerraformName(volume.Name)
		tf.WriteString(fmt.Sprintf(`resource "docker_volume" "%s" {
  name   = "%s"
  driver = "%s"
  
  labels = local.common_labels
}

`, resourceName, volume.Name, volume.Driver))
	}

	return os.WriteFile(c.BaseDir+"/docker/volumes.tf", []byte(tf.String()), 0644)
}

// generateWazuhModule creates the Wazuh volumes module
func (c *TerraformConfig) generateWazuhModule() error {
	if c.Infrastructure.Docker == nil || !hasWazuhVolumes(c.Infrastructure.Docker) {
		return nil
	}

	c.Logger.Info(" Generating Wazuh volumes module")

	// Generate module main.tf
	moduleMain := `resource "docker_volume" "this" {
  for_each = var.volumes

  name   = "${var.project}_${each.key}"
  driver = each.value.driver

  labels = merge(
    {
      "com.docker.compose.project" = var.project
      environment                   = var.environment
      managed_by                   = "terraform"
    },
    each.value.labels
  )
}
`

	if err := os.WriteFile(c.BaseDir+"/modules/wazuh-volumes/main.tf", []byte(moduleMain), 0644); err != nil {
		return err
	}

	// Generate module variables.tf
	moduleVars := `variable "project" {
  description = "Project name for volume naming"
  type        = string
}

variable "environment" {
  description = "Environment name"
  type        = string
}

variable "volumes" {
  description = "Map of volumes to create"
  type = map(object({
    driver = string
    labels = map(string)
  }))
}
`

	if err := os.WriteFile(c.BaseDir+"/modules/wazuh-volumes/variables.tf", []byte(moduleVars), 0644); err != nil {
		return err
	}

	// Generate module outputs.tf
	moduleOutputs := `output "volume_names" {
  description = "Names of created volumes"
  value       = [for v in docker_volume.this : v.name]
}

output "volume_ids" {
  description = "IDs of created volumes"
  value       = { for k, v in docker_volume.this : k => v.id }
}
`

	if err := os.WriteFile(c.BaseDir+"/modules/wazuh-volumes/outputs.tf", []byte(moduleOutputs), 0644); err != nil {
		return err
	}

	// Generate module usage in main docker file
	moduleUsage := `# Wazuh Volumes Module
# Manages all Wazuh-related Docker volumes

module "wazuh_volumes" {
  source = "./modules/wazuh-volumes"
  
  project     = "multi-node"
  environment = var.environment
  volumes     = var.volumes
}
`

	return os.WriteFile(c.BaseDir+"/docker/wazuh-volumes.tf", []byte(moduleUsage), 0644)
}

// generateHetznerResources creates Hetzner-specific configuration
func (c *TerraformConfig) generateHetznerResources() error {
	c.Logger.Info("☁️ Generating Hetzner resources")

	var tf strings.Builder
	tf.WriteString(`# Hetzner Cloud Resources
# Generated from infrastructure inspection

`)

	// Generate servers
	for _, server := range c.Infrastructure.Hetzner.Servers {
		resourceName := sanitizeTerraformName(server.Name)
		tf.WriteString(fmt.Sprintf(`resource "hcloud_server" "%s" {
  name        = "%s"
  server_type = "%s"
  image       = "%s"
  location    = "%s"
  
  labels = merge(local.common_labels, {
    datacenter = "%s"
    public_ip  = "%s"
  })
}

`, resourceName, server.Name, server.ServerType, server.Image, server.Location, server.Datacenter, server.PublicIP))
	}

	return os.WriteFile(c.BaseDir+"/hetzner/servers.tf", []byte(tf.String()), 0644)
}

// generateKVMResources creates KVM-specific configuration
func (c *TerraformConfig) generateKVMResources() error {
	c.Logger.Info(" Generating KVM resources")

	var tf strings.Builder
	tf.WriteString(`# KVM/Libvirt Resources
# Generated from infrastructure inspection

provider "libvirt" {
  uri = "qemu:///system"
}

`)

	// Generate VMs
	for _, vm := range c.Infrastructure.KVM.VMs {
		if vm.State == "shut off" {
			continue
		}

		resourceName := sanitizeTerraformName(vm.Name)
		tf.WriteString(fmt.Sprintf(`resource "libvirt_domain" "%s" {
  name     = "%s"
  memory   = "%s"
  vcpu     = %d
  
  autostart = true
  
  # Current state: %s
  # UUID: %s
}

`, resourceName, vm.Name, vm.Memory, vm.CPUs, vm.State, vm.UUID))
	}

	return os.WriteFile(c.BaseDir+"/kvm/domains.tf", []byte(tf.String()), 0644)
}

// generateEnvironmentFiles creates environment-specific tfvars files
func (c *TerraformConfig) generateEnvironmentFiles() error {
	c.Logger.Info(" Generating environment files")

	// Generate dev.tfvars
	devContent := `environment = "dev"
enable_monitoring = true

container_ports = {
`

	// Add detected ports from containers
	for _, container := range c.Infrastructure.Docker.Containers {
		if container.State == "running" && len(container.Ports) > 0 {
			for _, port := range container.Ports {
				if parts := strings.Split(port, "->"); len(parts) == 2 {
					hostPart := parts[0]
					containerPart := parts[1]

					if hostParts := strings.Split(hostPart, ":"); len(hostParts) == 2 {
						hostPort := hostParts[1]
						containerPort := strings.Split(containerPart, "/")[0]
						protocol := "tcp"
						if protocolParts := strings.Split(containerPart, "/"); len(protocolParts) == 2 {
							protocol = protocolParts[1]
						}

						devContent += fmt.Sprintf(`  %s = {
    internal = %s
    external = %s
    protocol = "%s"
  }
`, container.Name, containerPort, hostPort, protocol)
						break // Only first port for simplicity
					}
				}
			}
		}
	}

	devContent += "}\n\n# Wazuh volumes configuration\nvolumes = {\n"

	// Add Wazuh volumes
	for _, volume := range c.Infrastructure.Docker.Volumes {
		if strings.Contains(volume.Name, "wazuh") {
			// Extract the volume key from the full name
			nameParts := strings.Split(volume.Name, "_")
			if len(nameParts) >= 2 {
				volumeKey := nameParts[len(nameParts)-1]
				devContent += fmt.Sprintf(`  "%s" = {
    driver = "%s"
    labels = {}
  }
`, volumeKey, volume.Driver)
			}
		}
	}

	devContent += "}"

	if err := os.WriteFile(c.BaseDir+"/envs/dev.tfvars", []byte(devContent), 0644); err != nil {
		return err
	}

	// Generate prod.tfvars
	prodContent := `environment = "prod"
enable_monitoring = true

# Production port mappings - review and adjust
container_ports = {
  # Add your production port mappings here
}

# Production volumes configuration
volumes = {
  # Add your production volume configuration here
}
`

	return os.WriteFile(c.BaseDir+"/envs/prod.tfvars", []byte(prodContent), 0644)
}

// generateDocumentation creates README and usage documentation
func (c *TerraformConfig) generateDocumentation() error {
	c.Logger.Info(" Generating documentation")

	readmeContent := fmt.Sprintf(`# Infrastructure as Code - %s

Generated by Eos Infrastructure Inspector on %s

## Structure

`+"```"+`
.
├── main.tf              # Core Terraform configuration
├── variables.tf         # Input variables
├── outputs.tf          # Output values
├── docker/             # Docker resources
│   ├── containers.tf
│   ├── networks.tf
│   ├── volumes.tf
│   └── wazuh-volumes.tf
├── modules/            # Reusable modules
│   └── wazuh-volumes/
├── envs/              # Environment-specific configurations
│   ├── dev.tfvars
│   └── prod.tfvars
└── README.md          # This file
`+"```"+`

## Usage

### Initialize Terraform
`+"```bash"+`
terraform init
`+"```"+`

### Plan with environment
`+"```bash"+`
terraform plan -var-file="envs/dev.tfvars"
`+"```"+`

### Apply changes
`+"```bash"+`
terraform apply -var-file="envs/dev.tfvars"
`+"```"+`

## Import Existing Resources

Before applying, import existing resources:

`+"```bash"+`
`, c.Infrastructure.Hostname, c.Infrastructure.Timestamp.Format("2006-01-02 15:04:05 MST"))

	// Add import commands
	if c.Infrastructure.Docker != nil {
		for _, container := range c.Infrastructure.Docker.Containers {
			if container.State == "running" {
				resourceName := sanitizeTerraformName(container.Name)
				readmeContent += fmt.Sprintf("terraform import docker_container.%s %s\n", resourceName, container.Name)
			}
		}
	}

	readmeContent += "```" + `

## Security Notes

- Store state in remote backend (S3 configured)
- Use workspace isolation for environments
- Never commit sensitive data to version control
- Review all configurations before applying

## Generated Infrastructure Summary

`

	if c.Infrastructure.Docker != nil {
		readmeContent += fmt.Sprintf("- Docker Containers: %d\n", len(c.Infrastructure.Docker.Containers))
		readmeContent += fmt.Sprintf("- Docker Networks: %d\n", len(c.Infrastructure.Docker.Networks))
		readmeContent += fmt.Sprintf("- Docker Volumes: %d\n", len(c.Infrastructure.Docker.Volumes))
	}

	if c.Infrastructure.Hetzner != nil {
		readmeContent += fmt.Sprintf("- Hetzner Servers: %d\n", len(c.Infrastructure.Hetzner.Servers))
	}

	if c.Infrastructure.KVM != nil {
		readmeContent += fmt.Sprintf("- KVM Virtual Machines: %d\n", len(c.Infrastructure.KVM.VMs))
	}

	return os.WriteFile(c.BaseDir+"/README.md", []byte(readmeContent), 0644)
}
