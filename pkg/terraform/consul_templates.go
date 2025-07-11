// pkg/terraform/consul_templates.go

package terraform

const ConsulVaultIntegrationTemplate = `
terraform {
  required_providers {
    consul = {
      source  = "hashicorp/consul"
      version = "~> 2.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 3.0"
    }
  }
}

provider "consul" {
  address    = "{{.ConsulAddr}}"
  datacenter = "{{.Datacenter}}"
}

provider "vault" {
  address = "{{.VaultAddr}}"
}

{{if .UseServices}}
# Service discovery configuration
resource "consul_service" "terraform_managed" {
  name = "{{.ServicePrefix}}-service"
  tags = ["terraform", "managed"]
  
  check {
    id       = "{{.ServicePrefix}}-health"
    name     = "{{.ServicePrefix}} Health Check"
    http     = "http://localhost:8080/health"
    interval = "10s"
    timeout  = "5s"
  }
}
{{end}}

{{if .UseConsulKV}}
# Consul KV configuration
resource "consul_keys" "terraform_config" {
  key {
    path  = "{{.KVPrefix}}/config/version"
    value = "1.0.0"
  }
  
  key {
    path  = "{{.KVPrefix}}/config/environment"
    value = "production"
  }
}
{{end}}

{{if .UseVaultSecrets}}
# Vault secrets configuration
data "vault_generic_secret" "consul_tokens" {
  path = "consul/creds/terraform"
}

resource "consul_acl_token" "terraform" {
  description = "Token for Terraform operations"
  policies    = ["terraform-policy"]
  
  lifecycle {
    create_before_destroy = true
  }
}
{{end}}
`

const ConsulProviderConfig = `
provider "consul" {
  address    = "{{.ConsulAddr}}"
  datacenter = "{{.ConsulDatacenter}}"
  token      = var.consul_token
}

variable "consul_token" {
  description = "Consul ACL token"
  type        = string
  sensitive   = true
  default     = ""
}
`

const ConsulNetworkConfig = `
# Network configuration for Consul cluster
resource "hcloud_network" "consul_network" {
  name     = "{{.ClusterName}}-network"
  ip_range = "10.0.0.0/16"
}

resource "hcloud_network_subnet" "consul_subnet" {
  network_id   = hcloud_network.consul_network.id
  type         = "cloud"
  network_zone = "eu-central"
  ip_range     = "10.0.1.0/24"
}

resource "hcloud_firewall" "consul_firewall" {
  name = "{{.ClusterName}}-firewall"
  
  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "8300-8302"
    source_ips = ["10.0.0.0/16"]
  }
  
  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "8500"
    source_ips = ["0.0.0.0/0"]
  }
  
  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "8600"
    source_ips = ["10.0.0.0/16"]
  }
  
  rule {
    direction = "in"
    protocol  = "tcp"
    port      = "22"
    source_ips = ["0.0.0.0/0"]
  }
}
`

const ConsulServerConfig = `
# Consul server instances
resource "hcloud_server" "consul_servers" {
  count       = var.server_count
  name        = "${var.cluster_name}-server-${count.index + 1}"
  server_type = var.server_type
  image       = "ubuntu-22.04"
  location    = var.location
  
  ssh_keys = [var.ssh_key_name]
  
  user_data = templatefile("${path.module}/consul-server-init.yaml", {
    ConsulDatacenter  = var.consul_datacenter
    NodeIndex         = count.index + 1
    ConsulRetryJoin   = join(",", [for i in range(var.server_count) : "10.0.1.${i + 10}"])
    ConsulEncryptKey  = data.vault_kv_secret_v2.consul_config.data["encrypt_key"]
    ConsulServerCount = var.server_count
  })
  
  network {
    network_id = hcloud_network.consul_network.id
    ip         = "10.0.1.${count.index + 10}"
  }
  
  firewall_ids = [hcloud_firewall.consul_firewall.id]
  
  labels = {
    role        = "consul-server"
    datacenter  = var.consul_datacenter
    cluster     = var.cluster_name
  }
}
`

const ConsulClientConfig = `
# Consul client instances
resource "hcloud_server" "consul_clients" {
  count       = var.client_count
  name        = "${var.cluster_name}-client-${count.index + 1}"
  server_type = var.server_type
  image       = "ubuntu-22.04"
  location    = var.location
  
  ssh_keys = [var.ssh_key_name]
  
  user_data = templatefile("${path.module}/consul-client-init.yaml", {
    ConsulDatacenter = var.consul_datacenter
    NodeIndex        = count.index + 1
    ConsulRetryJoin  = join(",", [for i in range(var.server_count) : "10.0.1.${i + 10}"])
    ConsulEncryptKey = data.vault_kv_secret_v2.consul_config.data["encrypt_key"]
  })
  
  network {
    network_id = hcloud_network.consul_network.id
    ip         = "10.0.1.${count.index + 50}"
  }
  
  firewall_ids = [hcloud_firewall.consul_firewall.id]
  
  labels = {
    role        = "consul-client"
    datacenter  = var.consul_datacenter
    cluster     = var.cluster_name
  }
}
`

const ConsulClusterTemplate = `
terraform {
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.0"
    }
    consul = {
      source  = "hashicorp/consul"
      version = "~> 2.0"
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

provider "consul" {
  address    = "http://${hcloud_server.consul_servers[0].ipv4_address}:8500"
  datacenter = var.consul_datacenter
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

variable "consul_datacenter" {
  description = "Consul datacenter name"
  type        = string
  default     = "{{.ConsulDatacenter}}"
}

variable "cluster_name" {
  description = "Consul cluster name"
  type        = string
  default     = "{{.ClusterName}}"
}

variable "server_count" {
  description = "Number of Consul servers"
  type        = number
  default     = {{.ServerCount}}
}

variable "client_count" {
  description = "Number of Consul clients"
  type        = number
  default     = {{.ClientCount}}
}

variable "server_type" {
  description = "Hetzner server type"
  type        = string
  default     = "{{.ServerType}}"
}

variable "location" {
  description = "Hetzner location"
  type        = string
  default     = "{{.Location}}"
}

variable "ssh_key_name" {
  description = "SSH key name in Hetzner Cloud"
  type        = string
  default     = "{{.SSHKeyName}}"
}

# Retrieve secrets from Vault
data "vault_kv_secret_v2" "hetzner_token" {
  mount = "{{.SecretsMount}}"
  name  = "hetzner"
}

data "vault_kv_secret_v2" "consul_config" {
  mount = "{{.SecretsMount}}"
  name  = "consul"
}

data "vault_kv_secret_v2" "ssh_keys" {
  mount = "{{.SecretsMount}}"
  name  = "ssh"
}

# SSH key lookup
data "hcloud_ssh_key" "key" {
  name = var.ssh_key_name
}

# Consul server nodes
resource "hcloud_server" "consul_servers" {
  count       = var.server_count
  name        = "${var.cluster_name}-server-${count.index + 1}"
  image       = "ubuntu-22.04"
  server_type = var.server_type
  location    = var.location
  ssh_keys    = [data.hcloud_ssh_key.key.id]

  labels = {
    cluster = var.cluster_name
    role    = "consul-server"
    managed_by = "eos-terraform"
  }

  user_data = templatefile("${path.module}/consul-server-init.yaml", {
    consul_datacenter    = var.consul_datacenter
    consul_encrypt_key   = data.vault_kv_secret_v2.consul_config.data["encrypt_key"]
    consul_server_count  = var.server_count
    consul_retry_join    = join(",", [for i in range(var.server_count) : 
      "provider=hcloud tag_key=cluster tag_value=${var.cluster_name} tag_key=role tag_value=consul-server"
    ])
    node_index          = count.index + 1
    vault_addr          = var.vault_addr
  })
}

# Consul client nodes
resource "hcloud_server" "consul_clients" {
  count       = var.client_count
  name        = "${var.cluster_name}-client-${count.index + 1}"
  image       = "ubuntu-22.04"
  server_type = var.server_type
  location    = var.location
  ssh_keys    = [data.hcloud_ssh_key.key.id]

  labels = {
    cluster = var.cluster_name
    role    = "consul-client"
    managed_by = "eos-terraform"
  }

  user_data = templatefile("${path.module}/consul-client-init.yaml", {
    consul_datacenter    = var.consul_datacenter
    consul_encrypt_key   = data.vault_kv_secret_v2.consul_config.data["encrypt_key"]
    consul_retry_join    = join(",", hcloud_server.consul_servers[*].ipv4_address)
    vault_addr          = var.vault_addr
  })

  depends_on = [hcloud_server.consul_servers]
}

# Firewall for Consul
resource "hcloud_firewall" "consul" {
  name = "${var.cluster_name}-consul-firewall"
  
  # SSH access
  rule {
    direction = "in"
    port      = "22"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  # Consul HTTP API
  rule {
    direction = "in"
    port      = "8500"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  # Consul DNS
  rule {
    direction = "in"
    port      = "8600"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    port      = "8600"
    protocol  = "udp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  # Consul RPC
  rule {
    direction = "in"
    port      = "8300"
    protocol  = "tcp"
    source_ips = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  }

  # Consul Serf LAN
  rule {
    direction = "in"
    port      = "8301"
    protocol  = "tcp"
    source_ips = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  }

  rule {
    direction = "in"
    port      = "8301"
    protocol  = "udp"
    source_ips = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  }

  # Consul Serf WAN
  rule {
    direction = "in"
    port      = "8302"
    protocol  = "tcp"
    source_ips = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  }

  rule {
    direction = "in"
    port      = "8302"
    protocol  = "udp"
    source_ips = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  }

  # Connect sidecar proxy
  rule {
    direction = "in"
    port      = "21000-21255"
    protocol  = "tcp"
    source_ips = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  }
}

resource "hcloud_firewall_attachment" "consul_servers" {
  firewall_id = hcloud_firewall.consul.id
  server_ids  = hcloud_server.consul_servers[*].id
}

resource "hcloud_firewall_attachment" "consul_clients" {
  firewall_id = hcloud_firewall.consul.id
  server_ids  = hcloud_server.consul_clients[*].id
}

# Store cluster information in Vault
resource "vault_kv_secret_v2" "consul_cluster_info" {
  mount               = "{{.SecretsMount}}"
  name                = "{{.ClusterName}}/consul-cluster"
  cas                 = 1
  delete_all_versions = true
  
  data_json = jsonencode({
    cluster_name     = var.cluster_name
    datacenter       = var.consul_datacenter
    server_ips       = hcloud_server.consul_servers[*].ipv4_address
    client_ips       = hcloud_server.consul_clients[*].ipv4_address
    server_ids       = hcloud_server.consul_servers[*].id
    client_ids       = hcloud_server.consul_clients[*].id
    consul_url       = "http://${hcloud_server.consul_servers[0].ipv4_address}:8500"
    created_at       = timestamp()
  })
}

# Register services in Consul
resource "consul_service" "consul_ui" {
  name = "consul-ui"
  port = 8500
  tags = ["ui", "management"]

  check {
    http     = "http://${hcloud_server.consul_servers[0].ipv4_address}:8500/ui/"
    interval = "10s"
    timeout  = "3s"
  }
}

# Configure Consul KV for service configuration
resource "consul_keys" "service_config" {
  datacenter = var.consul_datacenter

  key {
    path  = "{{.KVPrefix}}/terraform/cluster_name"
    value = var.cluster_name
  }

  key {
    path  = "{{.KVPrefix}}/terraform/datacenter"
    value = var.consul_datacenter
  }

  key {
    path  = "{{.KVPrefix}}/config/global/vault_addr"
    value = var.vault_addr
  }
}

# Outputs
output "consul_server_ips" {
  description = "Consul server IP addresses"
  value       = hcloud_server.consul_servers[*].ipv4_address
}

output "consul_client_ips" {
  description = "Consul client IP addresses"
  value       = hcloud_server.consul_clients[*].ipv4_address
}

output "consul_ui_url" {
  description = "Consul UI URL"
  value       = "http://${hcloud_server.consul_servers[0].ipv4_address}:8500/ui/"
}

output "consul_api_url" {
  description = "Consul API URL"
  value       = "http://${hcloud_server.consul_servers[0].ipv4_address}:8500"
}
`

const ServiceMeshTemplate = `
terraform {
  required_providers {
    consul = {
      source  = "hashicorp/consul"
      version = "~> 2.0"
    }
    vault = {
      source  = "hashicorp/vault"
      version = "~> 3.0"
    }
  }
}

provider "consul" {
  address    = var.consul_addr
  datacenter = var.consul_datacenter
}

provider "vault" {
  address = var.vault_addr
  token   = var.vault_token
}

variable "consul_addr" {
  description = "Consul server address"
  type        = string
  default     = "{{.ConsulAddr}}"
}

variable "consul_datacenter" {
  description = "Consul datacenter"
  type        = string
  default     = "{{.ConsulDatacenter}}"
}

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

# Service mesh configuration
resource "consul_config_entry" "mesh" {
  kind = "mesh"
  name = "mesh"

  config_json = jsonencode({
    TransparentProxy = {
      MeshDestinationsOnly = false
    }
  })
}

# Service defaults for all services
resource "consul_config_entry" "global_proxy_defaults" {
  kind = "proxy-defaults"
  name = "global"

  config_json = jsonencode({
    Config = {
      protocol = "http"
    }
    MeshGateway = {
      Mode = "local"
    }
  })
}

{{range .Services}}
# Service: {{.Name}}
resource "consul_service" "{{.Name}}" {
  name = "{{.Name}}"
  port = {{.Port}}
  tags = {{.Tags}}

  {{if .Address}}
  address = "{{.Address}}"
  {{end}}

  {{if .Check}}
  check {
    {{if .Check.HTTP}}http = "{{.Check.HTTP}}"{{end}}
    {{if .Check.TCP}}tcp = "{{.Check.TCP}}"{{end}}
    interval = "{{.Check.Interval}}"
    timeout  = "{{.Check.Timeout}}"
    {{if .Check.DeregisterCriticalServiceAfter}}
    deregister_critical_service_after = "{{.Check.DeregisterCriticalServiceAfter}}"
    {{end}}
  }
  {{end}}

  {{if .Connect}}
  connect {
    native = {{.Connect.Native}}
    {{if .Connect.SidecarService}}
    sidecar_service {
      port = {{.Connect.SidecarService.Port}}
      {{if .Connect.SidecarService.Proxy}}
      proxy {
        {{range .Connect.SidecarService.Proxy.Upstreams}}
        upstreams {
          destination_name = "{{.DestinationName}}"
          local_bind_port  = {{.LocalBindPort}}
          {{if .Datacenter}}datacenter = "{{.Datacenter}}"{{end}}
        }
        {{end}}
        {{if .Connect.SidecarService.Proxy.Config}}
        config = {{.Connect.SidecarService.Proxy.Config}}
        {{end}}
      }
      {{end}}
    }
    {{end}}
  }
  {{end}}
}

# Service intentions for {{.Name}}
{{range .Intentions}}
resource "consul_intention" "{{$.Name}}_{{.Source}}" {
  source_name      = "{{.Source}}"
  destination_name = "{{$.Name}}"
  action          = "{{.Action}}"
  {{if .Description}}description = "{{.Description}}"{{end}}
}
{{end}}

# Service resolver for {{.Name}}
{{if .Resolver}}
resource "consul_config_entry" "{{.Name}}_resolver" {
  kind = "service-resolver"
  name = "{{.Name}}"

  config_json = jsonencode({
    {{if .Resolver.DefaultSubset}}DefaultSubset = "{{.Resolver.DefaultSubset}}"{{end}}
    {{if .Resolver.Subsets}}
    Subsets = {
      {{range $key, $value := .Resolver.Subsets}}
      "{{$key}}" = {
        Filter = "{{$value.Filter}}"
        {{if $value.OnlyPassing}}OnlyPassing = {{$value.OnlyPassing}}{{end}}
      }
      {{end}}
    }
    {{end}}
    {{if .Resolver.ConnectTimeout}}ConnectTimeout = "{{.Resolver.ConnectTimeout}}"{{end}}
    {{if .Resolver.RequestTimeout}}RequestTimeout = "{{.Resolver.RequestTimeout}}"{{end}}
  })
}
{{end}}

{{end}}

# Store service mesh configuration in Consul KV
resource "consul_keys" "service_mesh_config" {
  datacenter = var.consul_datacenter

  key {
    path  = "{{.KVPrefix}}/service-mesh/enabled"
    value = "true"
  }

  key {
    path  = "{{.KVPrefix}}/service-mesh/services"
    value = jsonencode([{{range .Services}}"{{.Name}}",{{end}}])
  }

  key {
    path  = "{{.KVPrefix}}/service-mesh/created_at"
    value = timestamp()
  }
}
`

const ConsulServerCloudInit = `#cloud-config
package_update: true
package_upgrade: true

packages:
  - curl
  - wget
  - unzip
  - jq

write_files:
  - path: /opt/consul/consul.hcl
    permissions: '0640'
    content: |
      datacenter = "{{.ConsulDatacenter}}"
      data_dir = "/opt/consul/data"
      log_level = "INFO"
      node_name = "consul-server-{{.NodeIndex}}"
      bind_addr = "0.0.0.0"
      client_addr = "0.0.0.0"
      retry_join = ["{{.ConsulRetryJoin}}"]
      server = true
      bootstrap_expect = {{.ConsulServerCount}}
      encrypt = "{{.ConsulEncryptKey}}"
      ui_config {
        enabled = true
      }
      connect {
        enabled = true
      }
      acl = {
        enabled = true
        default_policy = "allow"
        enable_token_persistence = true
      }
      
  - path: /opt/setup-consul.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      set -e
      
      # Download and install Consul
      CONSUL_VERSION="1.17.0"
      cd /tmp
      curl -O "https://releases.hashicorp.com/consul/${CONSUL_VERSION}/consul_${CONSUL_VERSION}_linux_amd64.zip"
      unzip "consul_${CONSUL_VERSION}_linux_amd64.zip"
      sudo mv consul /usr/local/bin/
      
      # Create consul user and directories
      sudo useradd --system --home /etc/consul.d --shell /bin/false consul
      sudo mkdir -p /opt/consul/data
      sudo mkdir -p /etc/consul.d
      sudo chown -R consul:consul /opt/consul
      sudo chown -R consul:consul /etc/consul.d
      
      # Copy configuration
      sudo cp /opt/consul/consul.hcl /etc/consul.d/
      sudo chown consul:consul /etc/consul.d/consul.hcl
      
      # Create systemd service
      cat <<EOF | sudo tee /etc/systemd/system/consul.service
[Unit]
Description=Consul
Documentation=https://www.consul.io/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/consul.d/consul.hcl

[Service]
Type=notify
User=consul
Group=consul
ExecStart=/usr/local/bin/consul agent -config-dir=/etc/consul.d/
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
      
      # Start Consul
      sudo systemctl daemon-reload
      sudo systemctl enable consul
      sudo systemctl start consul
      
      # Wait for Consul to be ready
      while ! consul members; do
        echo "Waiting for Consul to be ready..."
        sleep 5
      done
      
      echo "Consul server setup completed"

runcmd:
  - /opt/setup-consul.sh
`

const ConsulClientCloudInit = `#cloud-config
package_update: true
package_upgrade: true

packages:
  - curl
  - wget
  - unzip
  - jq

write_files:
  - path: /opt/consul/consul.hcl
    permissions: '0640'
    content: |
      datacenter = "{{.ConsulDatacenter}}"
      data_dir = "/opt/consul/data"
      log_level = "INFO"
      node_name = "consul-client-${HOSTNAME}"
      bind_addr = "0.0.0.0"
      client_addr = "0.0.0.0"
      retry_join = [{{.ConsulRetryJoin}}]
      server = false
      encrypt = "{{.ConsulEncryptKey}}"
      connect {
        enabled = true
      }
      acl = {
        enabled = true
        default_policy = "allow"
        enable_token_persistence = true
      }
      
  - path: /opt/setup-consul.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      set -e
      
      # Download and install Consul
      CONSUL_VERSION="1.17.0"
      cd /tmp
      curl -O "https://releases.hashicorp.com/consul/${CONSUL_VERSION}/consul_${CONSUL_VERSION}_linux_amd64.zip"
      unzip "consul_${CONSUL_VERSION}_linux_amd64.zip"
      sudo mv consul /usr/local/bin/
      
      # Create consul user and directories
      sudo useradd --system --home /etc/consul.d --shell /bin/false consul
      sudo mkdir -p /opt/consul/data
      sudo mkdir -p /etc/consul.d
      sudo chown -R consul:consul /opt/consul
      sudo chown -R consul:consul /etc/consul.d
      
      # Copy configuration
      sudo cp /opt/consul/consul.hcl /etc/consul.d/
      sudo chown consul:consul /etc/consul.d/consul.hcl
      
      # Create systemd service
      cat <<EOF | sudo tee /etc/systemd/system/consul.service
[Unit]
Description=Consul
Documentation=https://www.consul.io/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/consul.d/consul.hcl

[Service]
Type=notify
User=consul
Group=consul
ExecStart=/usr/local/bin/consul agent -config-dir=/etc/consul.d/
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
      
      # Start Consul
      sudo systemctl daemon-reload
      sudo systemctl enable consul
      sudo systemctl start consul
      
      # Wait for Consul to join cluster
      while ! consul members; do
        echo "Waiting for Consul to join cluster..."
        sleep 5
      done
      
      echo "Consul client setup completed"

runcmd:
  - /opt/setup-consul.sh
`

// ConsulTemplateData contains data for generating Consul-integrated templates
type ConsulTemplateData struct {
	VaultAddr         string
	ConsulAddr        string
	ConsulDatacenter  string
	SecretsMount      string
	KVPrefix          string
	ClusterName       string
	ServerCount       int
	ClientCount       int
	ServerType        string
	Location          string
	SSHKeyName        string
	Services          []ConsulServiceTemplate
	NodeIndex         int
	ConsulRetryJoin   string
	ConsulEncryptKey  string
	ConsulServerCount int
	EncryptKey        string
	EnableACL         bool
	EnableTLS         bool
	ConsulVersion     string
	ConsulPort        int
}

// ConsulServiceTemplate represents a service configuration for templates
type ConsulServiceTemplate struct {
	Name       string
	Port       int
	Address    string
	Tags       []string
	Check      *ConsulHealthCheck
	Connect    *ConsulConnect
	Intentions []ConsulIntention
	Resolver   *ConsulResolver
}

// ConsulIntention represents a service intention
type ConsulIntention struct {
	Source      string
	Action      string
	Description string
}

// ConsulResolver represents a service resolver configuration
type ConsulResolver struct {
	DefaultSubset  string
	Subsets        map[string]ConsulSubset
	ConnectTimeout string
	RequestTimeout string
}

// ConsulSubset represents a service subset
type ConsulSubset struct {
	Filter      string
	OnlyPassing bool
}

// ServiceMeshTemplateData holds data for service mesh configuration
type ServiceMeshTemplateData struct {
	ServiceName   string
	Datacenter    string
	EnableMetrics bool
	EnableTracing bool
	ConsulPort    int
	Upstreams     []UpstreamService
	Intentions    []ServiceIntention
	ConsulAddr    string
	VaultAddr     string
	KVPrefix      string
	Services      []ConsulServiceTemplate
}
