// pkg/terraform/vault_templates.go

package terraform

const VaultProviderTemplate = `
terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 3.0"
    }
    {{range .Providers}}
    {{.Name}} = {
      source  = "{{.Source}}"
      version = "{{.Version}}"
    }
    {{end}}
  }
}

provider "vault" {
  address = var.vault_addr
  token   = var.vault_token
}

{{range .Providers}}
{{.Config}}
{{end}}

variable "vault_addr" {
  description = "Vault server address"
  type        = string
  default     = "{{.VaultAddr}}"
}

variable "vault_token" {
  description = "Vault authentication token"
  type        = string
  sensitive   = true
}
`

const VaultBackendTemplate = `
terraform {
  backend "http" {
    address        = "{{.Address}}/v1/{{.Path}}"
    lock_address   = "{{.Address}}/v1/{{.Path}}-lock"
    unlock_address = "{{.Address}}/v1/{{.Path}}-lock"
    username       = "terraform"
    password       = var.vault_token
    lock_method    = "PUT"
    unlock_method  = "DELETE"
    retry_max      = 5
    retry_wait_min = 1
    retry_wait_max = 10
  }
}
`

const VaultSecretDataSourceTemplate = `
# Vault secret data sources
{{range .SecretReferences}}
data "vault_kv_secret_v2" "{{.VarName}}" {
  mount = "{{.Mount}}"
  name  = "{{.SecretName}}"
}

variable "{{.VarName}}" {
  description = "{{.Description}}"
  type        = string
  sensitive   = {{.Sensitive}}
  default     = data.vault_kv_secret_v2.{{.VarName}}.data["{{.Key}}"]
}
{{end}}
`

const HetznerVaultTemplate = `
terraform {
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 3.0"
    }
  }
}

provider "vault" {
  address = var.vault_addr
  token   = var.vault_token
}

provider "hcloud" {
  token = data.vault_kv_secret_v2.hetzner_token.data["token"]
}

# Vault configuration
variable "vault_addr" {
  description = "Vault server address"
  type        = string
  default     = "{{.VaultAddr}}"
}

variable "vault_token" {
  description = "Vault authentication token"
  type        = string
  sensitive   = true
}

# Retrieve Hetzner token from Vault
data "vault_kv_secret_v2" "hetzner_token" {
  mount = "{{.SecretsMount}}"
  name  = "hetzner"
}

# Retrieve SSH key from Vault
data "vault_kv_secret_v2" "ssh_keys" {
  mount = "{{.SecretsMount}}"
  name  = "ssh"
}

# Server configuration variables
variable "server_name" {
  description = "Name of the server"
  type        = string
  default     = "{{.ServerName}}"
}

variable "server_type" {
  description = "Server type"
  type        = string
  default     = "{{.ServerType}}"
}

variable "location" {
  description = "Server location"
  type        = string
  default     = "{{.Location}}"
}

variable "ssh_key_name" {
  description = "SSH key name in Hetzner Cloud"
  type        = string
  default     = "{{.SSHKeyName}}"
}

# Server resources
data "hcloud_ssh_key" "key" {
  name = var.ssh_key_name
}

resource "hcloud_server" "server" {
  name        = var.server_name
  image       = "ubuntu-22.04"
  server_type = var.server_type
  location    = var.location
  ssh_keys    = [data.hcloud_ssh_key.key.id]

  labels = {
    project = "{{.ProjectName}}"
    managed_by = "eos-terraform"
  }

  user_data = templatefile("${path.module}/cloud-init.yaml", {
    ssh_public_key = data.vault_kv_secret_v2.ssh_keys.data["public_key"]
  })
}

# Store server information back to Vault
resource "vault_kv_secret_v2" "server_info" {
  mount               = "{{.SecretsMount}}"
  name                = "{{.ProjectName}}/server"
  cas                 = 1
  delete_all_versions = true
  
  data_json = jsonencode({
    server_id    = hcloud_server.server.id
    server_ip    = hcloud_server.server.ipv4_address
    server_ipv6  = hcloud_server.server.ipv6_address
    server_name  = hcloud_server.server.name
    created_at   = timestamp()
  })
}

# Outputs
output "server_ip" {
  description = "Server IPv4 address"
  value       = hcloud_server.server.ipv4_address
}

output "server_ipv6" {
  description = "Server IPv6 address"
  value       = hcloud_server.server.ipv6_address
}

output "server_id" {
  description = "Server ID"
  value       = hcloud_server.server.id
}
`

const K3sVaultTemplate = `
terraform {
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 3.0"
    }
  }
}

provider "vault" {
  address = var.vault_addr
  token   = var.vault_token
}

provider "hcloud" {
  token = data.vault_kv_secret_v2.hetzner_token.data["token"]
}

# Vault configuration
variable "vault_addr" {
  description = "Vault server address"
  type        = string
  default     = "{{.VaultAddr}}"
}

variable "vault_token" {
  description = "Vault authentication token"
  type        = string
  sensitive   = true
}

# Retrieve secrets from Vault
data "vault_kv_secret_v2" "hetzner_token" {
  mount = "{{.SecretsMount}}"
  name  = "hetzner"
}

data "vault_kv_secret_v2" "k3s_config" {
  mount = "{{.SecretsMount}}"
  name  = "k3s"
}

data "vault_kv_secret_v2" "ssh_keys" {
  mount = "{{.SecretsMount}}"
  name  = "ssh"
}

# K3s configuration variables
variable "cluster_name" {
  description = "K3s cluster name"
  type        = string
  default     = "{{.ClusterName}}"
}

variable "node_count" {
  description = "Number of K3s nodes"
  type        = number
  default     = {{.NodeCount}}
}

variable "server_type" {
  description = "Server type for K3s nodes"
  type        = string
  default     = "{{.ServerType}}"
}

variable "location" {
  description = "Server location"
  type        = string
  default     = "{{.Location}}"
}

variable "ssh_key_name" {
  description = "SSH key name in Hetzner Cloud"
  type        = string
  default     = "{{.SSHKeyName}}"
}

# SSH key lookup
data "hcloud_ssh_key" "key" {
  name = var.ssh_key_name
}

# K3s server node
resource "hcloud_server" "k3s_server" {
  name        = "${var.cluster_name}-server"
  image       = "ubuntu-22.04"
  server_type = var.server_type
  location    = var.location
  ssh_keys    = [data.hcloud_ssh_key.key.id]

  labels = {
    cluster = var.cluster_name
    role    = "server"
    managed_by = "eos-terraform"
  }

  user_data = templatefile("${path.module}/k3s-server-init.yaml", {
    k3s_token = data.vault_kv_secret_v2.k3s_config.data["token"]
    vault_addr = var.vault_addr
    cluster_name = var.cluster_name
  })
}

# K3s agent nodes
resource "hcloud_server" "k3s_agents" {
  count       = var.node_count - 1
  name        = "${var.cluster_name}-agent-${count.index + 1}"
  image       = "ubuntu-22.04"
  server_type = var.server_type
  location    = var.location
  ssh_keys    = [data.hcloud_ssh_key.key.id]

  labels = {
    cluster = var.cluster_name
    role    = "agent"
    managed_by = "eos-terraform"
  }

  user_data = templatefile("${path.module}/k3s-agent-init.yaml", {
    k3s_token      = data.vault_kv_secret_v2.k3s_config.data["token"]
    k3s_server_url = "https://${hcloud_server.k3s_server.ipv4_address}:6443"
    vault_addr     = var.vault_addr
    cluster_name   = var.cluster_name
  })

  depends_on = [hcloud_server.k3s_server]
}

# Firewall for K3s
resource "hcloud_firewall" "k3s" {
  name = "${var.cluster_name}-firewall"
  
  rule {
    direction = "in"
    port      = "22"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    port      = "6443"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    port      = "10250"
    protocol  = "tcp"
    source_ips = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  }

  rule {
    direction = "in"
    port      = "8472"
    protocol  = "udp"
    source_ips = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  }
}

resource "hcloud_firewall_attachment" "k3s_server" {
  firewall_id = hcloud_firewall.k3s.id
  server_ids  = [hcloud_server.k3s_server.id]
}

resource "hcloud_firewall_attachment" "k3s_agents" {
  firewall_id = hcloud_firewall.k3s.id
  server_ids  = hcloud_server.k3s_agents[*].id
}

# Store cluster information in Vault
resource "vault_kv_secret_v2" "cluster_info" {
  mount               = "{{.SecretsMount}}"
  name                = "{{.ClusterName}}/cluster"
  cas                 = 1
  delete_all_versions = true
  
  data_json = jsonencode({
    cluster_name    = var.cluster_name
    server_ip       = hcloud_server.k3s_server.ipv4_address
    server_id       = hcloud_server.k3s_server.id
    agent_ips       = hcloud_server.k3s_agents[*].ipv4_address
    agent_ids       = hcloud_server.k3s_agents[*].id
    kubeconfig_url  = "https://${hcloud_server.k3s_server.ipv4_address}:6443"
    created_at      = timestamp()
  })
}

# Outputs
output "k3s_server_ip" {
  description = "K3s server IP address"
  value       = hcloud_server.k3s_server.ipv4_address
}

output "k3s_agent_ips" {
  description = "K3s agent IP addresses"
  value       = hcloud_server.k3s_agents[*].ipv4_address
}

output "kubeconfig_command" {
  description = "Command to get kubeconfig"
  value       = "scp root@${hcloud_server.k3s_server.ipv4_address}:/etc/rancher/k3s/k3s.yaml ./kubeconfig && sed -i 's/127.0.0.1/${hcloud_server.k3s_server.ipv4_address}/g' ./kubeconfig"
}
`

const VaultK3sServerCloudInit = `#cloud-config
package_update: true
package_upgrade: true

packages:
  - curl
  - wget
  - jq

write_files:
  - path: /opt/setup-k3s-server.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      set -e
      
      # Install K3s server
      curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--tls-san $(hostname -I | awk '{print $1}')" K3S_TOKEN="{{.K3sToken}}" sh -
      
      # Wait for K3s to be ready
      until kubectl get nodes; do
        echo "Waiting for K3s to be ready..."
        sleep 5
      done
      
      # Store kubeconfig in Vault (if vault CLI is available)
      if command -v vault &> /dev/null; then
        export VAULT_ADDR="{{.VaultAddr}}"
        vault kv put terraform/{{.ClusterName}}/kubeconfig data="$(cat /etc/rancher/k3s/k3s.yaml | base64 -w 0)"
      fi

runcmd:
  - /opt/setup-k3s-server.sh
  - systemctl enable k3s
  - systemctl start k3s
`

const VaultK3sAgentCloudInit = `#cloud-config
package_update: true
package_upgrade: true

packages:
  - curl
  - wget

write_files:
  - path: /opt/setup-k3s-agent.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      set -e
      
      # Install K3s agent
      curl -sfL https://get.k3s.io | K3S_URL="{{.K3sServerURL}}" K3S_TOKEN="{{.K3sToken}}" sh -
      
      # Wait for connection
      until systemctl is-active k3s-agent; do
        echo "Waiting for K3s agent to be active..."
        sleep 5
      done

runcmd:
  - /opt/setup-k3s-agent.sh
  - systemctl enable k3s-agent
  - systemctl start k3s-agent
`

// VaultTemplateData contains data for generating Vault-integrated templates
type VaultTemplateData struct {
	VaultAddr    string
	SecretsMount string
	ProjectName  string
	ServerName   string
	ServerType   string
	Location     string
	SSHKeyName   string
	ClusterName  string
	NodeCount    int
	K3sToken     string
	K3sServerURL string
	Providers    []ProviderConfig
}

// VaultSecretRef represents a reference to a Vault secret in templates
type VaultSecretRef struct {
	VarName     string
	Mount       string
	SecretName  string
	Key         string
	Description string
	Sensitive   bool
}
