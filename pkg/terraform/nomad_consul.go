// pkg/terraform/nomad_consul.go
package terraform

import (
	"fmt"

	"github.com/CodeMonkeyCybersecurity/eos/pkg/shared"
)

// NomadConsulTemplate replaces K3s/Kubernetes Terraform templates with Nomad+Consul
const NomadConsulTemplate = `
terraform {
  required_providers {
    nomad = {
      source  = "hashicorp/nomad"
      version = "~> 2.0"
    }
    consul = {
      source  = "hashicorp/consul"
      version = "~> 2.0"
    }
    {{if .CloudDeploy}}
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.0"
    }
    {{end}}
  }
}

{{if .CloudDeploy}}
# Cloud Infrastructure (Hetzner)
provider "hcloud" {
  token = var.hcloud_token
}

variable "hcloud_token" {
  description = "Hetzner Cloud API Token"
  type        = string
  sensitive   = true
}

variable "ssh_key_name" {
  description = "SSH key name in Hetzner Cloud"
  type        = string
}

resource "hcloud_server" "nomad_cluster" {
  count       = {{.NodeCount}}
  name        = "{{.ClusterName}}-node-${count.index + 1}"
  image       = "ubuntu-22.04"
  server_type = "{{.ServerType}}"
  location    = "{{.Location}}"
  ssh_keys    = [data.hcloud_ssh_key.key.id]

  user_data = templatefile("${path.module}/nomad-consul-init.yaml", {
    domain         = var.domain
    cluster_name   = "{{.ClusterName}}"
    node_index     = count.index + 1
    is_server      = count.index < {{.ServerCount}}
    consul_servers = join(",", [for i in range({{.ServerCount}}) : "{{.ClusterName}}-node-${i + 1}"])
    nomad_servers  = join(",", [for i in range({{.ServerCount}}) : "{{.ClusterName}}-node-${i + 1}"])
  })

  labels = {
    type = count.index < {{.ServerCount}} ? "nomad-consul-server" : "nomad-consul-client"
    cluster = "{{.ClusterName}}"
    role = count.index < {{.ServerCount}} ? "server" : "client"
  }
}

data "hcloud_ssh_key" "key" {
  name = var.ssh_key_name
}

# Firewall for Nomad + Consul + HTTP/HTTPS
resource "hcloud_firewall" "nomad_consul_cluster" {
  name = "{{.ClusterName}}-firewall"
  
  # SSH
  rule {
    direction = "in"
    port      = "22"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  # Nomad HTTP API
  rule {
    direction = "in"
    port      = "4646"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  # Nomad RPC
  rule {
    direction = "in"
    port      = "4647"
    protocol  = "tcp"
    source_ips = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  }

  # Nomad Serf
  rule {
    direction = "in"
    port      = "4648"
    protocol  = "tcp"
    source_ips = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  }

  rule {
    direction = "in"
    port      = "4648"
    protocol  = "udp"
    source_ips = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  }

  # Consul HTTP API
  rule {
    direction = "in"
    port      = "8500"
    protocol  = "tcp"
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

  # HTTP/HTTPS (for ingress)
  rule {
    direction = "in"
    port      = "80"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    port      = "443"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  # Mail ports (if enabled)
  {{range .MailPorts}}
  rule {
    direction = "in"
    port      = "{{.}}"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
  {{end}}

  # Dynamic port range for Nomad tasks
  rule {
    direction = "in"
    port      = "20000-32000"
    protocol  = "tcp"
    source_ips = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  }
}

resource "hcloud_firewall_attachment" "nomad_consul_cluster" {
  firewall_id = hcloud_firewall.nomad_consul_cluster.id
  server_ids  = hcloud_server.nomad_cluster[*].id
}

# Load Balancer for external access
resource "hcloud_load_balancer" "nomad_consul_lb" {
  name               = "{{.ClusterName}}-lb"
  load_balancer_type = "lb11"
  location           = "{{.Location}}"
}

resource "hcloud_load_balancer_target" "nomad_consul_lb_targets" {
  count            = length(hcloud_server.nomad_cluster)
  type             = "server"
  load_balancer_id = hcloud_load_balancer.nomad_consul_lb.id
  server_id        = hcloud_server.nomad_cluster[count.index].id
}

# HTTP service
resource "hcloud_load_balancer_service" "http" {
  load_balancer_id = hcloud_load_balancer.nomad_consul_lb.id
  protocol         = "http"
  listen_port      = 80
  destination_port = 80
  
  health_check {
    protocol = "http"
    port     = 80
    path     = "/health"
    interval = 15
    timeout  = 10
    retries  = 3
  }
}

# HTTPS service
resource "hcloud_load_balancer_service" "https" {
  load_balancer_id = hcloud_load_balancer.nomad_consul_lb.id
  protocol         = "tcp"
  listen_port      = 443
  destination_port = 443
}

# Nomad UI service
resource "hcloud_load_balancer_service" "nomad_ui" {
  load_balancer_id = hcloud_load_balancer.nomad_consul_lb.id
  protocol         = "http"
  listen_port      = 4646
  destination_port = 4646
  
  health_check {
    protocol = "http"
    port     = 4646
    path     = "/v1/status/leader"
    interval = 15
    timeout  = 10
    retries  = 3
  }
}

# Consul UI service
resource "hcloud_load_balancer_service" "consul_ui" {
  load_balancer_id = hcloud_load_balancer.nomad_consul_lb.id
  protocol         = "http"
  listen_port      = 8500
  destination_port = 8500
  
  health_check {
    protocol = "http"
    port     = 8500
    path     = "/v1/status/leader"
    interval = 15
    timeout  = 10
    retries  = 3
  }
}

output "server_ips" {
  value = hcloud_server.nomad_cluster[*].ipv4_address
}

output "load_balancer_ip" {
  value = hcloud_load_balancer.nomad_consul_lb.ipv4
}

output "nomad_servers" {
  value = [for i, server in hcloud_server.nomad_cluster : server.ipv4_address if i < {{.ServerCount}}]
}

output "consul_servers" {
  value = [for i, server in hcloud_server.nomad_cluster : server.ipv4_address if i < {{.ServerCount}}]
}
{{end}}

# Nomad provider configuration
provider "nomad" {
  {{if .CloudDeploy}}
  address = "http://${hcloud_load_balancer.nomad_consul_lb.ipv4}:4646"
  {{else}}
  address = "http://localhost:4646"
  {{end}}
}

# Consul provider configuration
provider "consul" {
  {{if .CloudDeploy}}
  address = "${hcloud_load_balancer.nomad_consul_lb.ipv4}:8500"
  {{else}}
  address = "{{.ConsulAddress}}"
  {{end}}
}

# Deploy ingress infrastructure via Nomad jobs
resource "nomad_job" "caddy_ingress" {
  jobspec = templatefile("${path.module}/jobs/caddy-ingress.nomad", {
    domain = var.domain
    datacenter = "{{.Datacenter}}"
    region = "{{.Region}}"
    replicas = {{.CaddyReplicas}}
    version = "{{.CaddyVersion}}"
    admin_enabled = {{.CaddyAdminEnabled}}
    cpu_request = {{.CaddyCPURequest}}
    memory_request = {{.CaddyMemoryRequest}}
  })

  depends_on = [
    {{if .CloudDeploy}}hcloud_server.nomad_cluster{{else}}null_resource.nomad_ready{{end}}
  ]
}

{{if .EnableMailProxy}}
resource "nomad_job" "nginx_mail_proxy" {
  jobspec = templatefile("${path.module}/jobs/nginx-mail.nomad", {
    domain = var.domain
    datacenter = "{{.Datacenter}}"
    region = "{{.Region}}"
    replicas = {{.NginxReplicas}}
    version = "{{.NginxVersion}}"
    mail_ports = {{.MailPorts}}
    mail_backend = "{{.MailBackend}}"
    cpu_request = {{.NginxCPURequest}}
    memory_request = {{.NginxMemoryRequest}}
  })

  depends_on = [
    nomad_job.caddy_ingress
  ]
}
{{end}}

# Consul service registrations for external services
{{range .ExternalServices}}
resource "consul_service" "{{.Name}}" {
  name    = "{{.Name}}"
  port    = {{.Port}}
  tags    = [{{range .Tags}}"{{.}}",{{end}}]
  
  check {
    http     = "http://{{.Address}}:{{.Port}}/health"
    interval = "30s"
    timeout  = "5s"
  }
}
{{end}}

# Variables
variable "domain" {
  description = "Primary domain for the cluster"
  type        = string
}

{{if .CloudDeploy}}
variable "node_count" {
  description = "Total number of nodes in the cluster"
  type        = number
  default     = {{.NodeCount}}
}

variable "server_count" {
  description = "Number of server nodes"
  type        = number
  default     = {{.ServerCount}}
}
{{end}}

# Outputs
output "cluster_info" {
  value = {
    cluster_name = "{{.ClusterName}}"
    datacenter = "{{.Datacenter}}"
    region = "{{.Region}}"
    {{if .CloudDeploy}}
    node_count = {{.NodeCount}}
    server_count = {{.ServerCount}}
    {{end}}
    ingress_enabled = true
    mail_proxy_enabled = {{.EnableMailProxy}}
  }
}

output "access_urls" {
  value = {
    {{if .CloudDeploy}}
    domain = var.domain
    nomad_ui = "http://${hcloud_load_balancer.nomad_consul_lb.ipv4}:4646"
    consul_ui = "http://${hcloud_load_balancer.nomad_consul_lb.ipv4}:8500"
    ingress_http = "http://${hcloud_load_balancer.nomad_consul_lb.ipv4}"
    ingress_https = "https://${hcloud_load_balancer.nomad_consul_lb.ipv4}"
    {{else}}
    domain = var.domain
    nomad_ui = "http://localhost:4646"
    consul_ui = "http://localhost:8500"
    ingress_http = "http://localhost"
    ingress_https = "https://localhost"
    {{end}}
  }
}
`

// NomadConsulCloudInit replaces K3s cloud-init with Nomad+Consul setup
const NomadConsulCloudInit = `#cloud-config
package_update: true
package_upgrade: true

packages:
  - curl
  - wget
  - unzip
  - apt-transport-https
  - ca-certificates
  - gnupg
  - lsb-release
  - docker.io

users:
  - name: nomad
    system: true
    shell: /bin/false
    home: /var/lib/nomad
  - name: consul
    system: true
    shell: /bin/false
    home: /var/lib/consul

write_files:
  - path: /opt/bootstrap-nomad-consul.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      set -euo pipefail
      
      echo "Bootstrapping Nomad + Consul cluster..."
      
      # Variables from template
      NODE_INDEX=${node_index}
      IS_SERVER=${is_server}
      CONSUL_SERVERS="${consul_servers}"
      NOMAD_SERVERS="${nomad_servers}"
      DOMAIN="${domain}"
      
      # Get latest versions
      NOMAD_VERSION="1.7.2"
      CONSUL_VERSION="1.17.0"
      
      # Install Consul
      cd /tmp
      wget -q "https://releases.hashicorp.com/consul/$${CONSUL_VERSION}/consul_$${CONSUL_VERSION}_linux_amd64.zip"
      unzip consul_$${CONSUL_VERSION}_linux_amd64.zip
      sudo mv consul /usr/local/bin/
      sudo chmod +x /usr/local/bin/consul
      
      # Install Nomad
      wget -q "https://releases.hashicorp.com/nomad/$${NOMAD_VERSION}/nomad_$${NOMAD_VERSION}_linux_amd64.zip"
      unzip nomad_$${NOMAD_VERSION}_linux_amd64.zip
      sudo mv nomad /usr/local/bin/
      sudo chmod +x /usr/local/bin/nomad
      
      # Create directories
      sudo mkdir -p /etc/consul.d /var/lib/consul /var/log/consul
      sudo mkdir -p /etc/nomad.d /var/lib/nomad /var/log/nomad
      sudo chown consul:consul /var/lib/consul /var/log/consul
      sudo chown nomad:nomad /var/lib/nomad /var/log/nomad
      
      # Get node IP
      NODE_IP=$(curl -s http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address || hostname -I | awk '{print $1}')
      
      # Generate Consul configuration
      cat > /tmp/consul.hcl <<EOF
datacenter = "dc1"
data_dir = "/var/lib/consul"
log_level = "INFO"
log_file = "/var/log/consul/"
bind_addr = "$${NODE_IP}"
client_addr = "0.0.0.0"

$(if [[ "$${IS_SERVER}" == "true" ]]; then
  echo "server = true"
  echo "bootstrap_expect = 3"
  echo "ui_config { enabled = true }"
  echo "connect { enabled = true }"
  # Convert comma-separated servers to retry_join array
  IFS=',' read -ra SERVERS <<< "$${CONSUL_SERVERS}"
  echo "retry_join = ["
  for server in "$${SERVERS[@]}"; do
    if [[ "$${server}" != "\${HOSTNAME}" ]]; then
      echo "  \"$${server}\","
    fi
  done
  echo "]"
else
  echo "server = false"
  echo "retry_join = ["
  IFS=',' read -ra SERVERS <<< "$${CONSUL_SERVERS}"
  for server in "$${SERVERS[@]}"; do
    echo "  \"$${server}\","
  done
  echo "]"
fi)

ports {
  grpc = 8502
}

acl = {
  enabled = true
  default_policy = "allow"
  enable_token_persistence = true
}
EOF

      sudo mv /tmp/consul.hcl /etc/consul.d/
      
      # Generate Nomad configuration
      cat > /tmp/nomad.hcl <<EOF
datacenter = "dc1"
region = "global"
data_dir = "/var/lib/nomad"
log_level = "INFO"
log_file = "/var/log/nomad/"
bind_addr = "$${NODE_IP}"

$(if [[ "$${IS_SERVER}" == "true" ]]; then
  echo "server {"
  echo "  enabled = true"
  echo "  bootstrap_expect = 3"
  echo "}"
  echo "client {"
  echo "  enabled = true"
  echo "}"
else
  echo "server {"
  echo "  enabled = false"
  echo "}"
  echo "client {"
  echo "  enabled = true"
  IFS=',' read -ra SERVERS <<< "$${NOMAD_SERVERS}"
  echo "  servers = ["
  for server in "$${SERVERS[@]}"; do
    echo "    \"$${server}:4647\","
  done
  echo "  ]"
  echo "}"
fi)

ui_config {
  enabled = true
}

consul {
  address = "{{.ConsulAddress}}"
}

telemetry {
  collection_interval = "1s"
  disable_hostname = true
  prometheus_metrics = true
  publish_allocation_metrics = true
  publish_node_metrics = true
}

plugin "docker" {
  config {
    allow_privileged = false
    volumes {
      enabled = true
    }
  }
}
EOF

      sudo mv /tmp/nomad.hcl /etc/nomad.d/
      
      # Create systemd services
      cat > /tmp/consul.service <<EOF
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

      cat > /tmp/nomad.service <<EOF
[Unit]
Description=Nomad
Documentation=https://www.nomadproject.io/
Requires=network-online.target
After=network-online.target consul.service
ConditionFileNotEmpty=/etc/nomad.d/nomad.hcl

[Service]
Type=notify
User=nomad
Group=nomad
ExecStart=/usr/local/bin/nomad agent -config=/etc/nomad.d/nomad.hcl
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

      sudo mv /tmp/consul.service /etc/systemd/system/
      sudo mv /tmp/nomad.service /etc/systemd/system/
      
      # Enable and start services
      sudo systemctl daemon-reload
      sudo systemctl enable consul nomad
      sudo systemctl start consul
      sleep 10
      sudo systemctl start nomad
      
      echo "Nomad + Consul bootstrap completed"

runcmd:
  - /opt/bootstrap-nomad-consul.sh

final_message: "Nomad + Consul cluster node is ready!"
`

// NomadConsulConfig represents configuration for Nomad+Consul Terraform deployment
type NomadConsulConfig struct {
	CloudDeploy bool   `json:"cloud_deploy"`
	ClusterName string `json:"cluster_name"`
	ServerType  string `json:"server_type"`
	Location    string `json:"location"`
	NodeCount   int    `json:"node_count"`
	ServerCount int    `json:"server_count"`
	Datacenter  string `json:"datacenter"`
	Region      string `json:"region"`

	// Ingress configuration
	CaddyReplicas      int    `json:"caddy_replicas"`
	CaddyVersion       string `json:"caddy_version"`
	CaddyAdminEnabled  bool   `json:"caddy_admin_enabled"`
	CaddyCPURequest    int    `json:"caddy_cpu_request"`
	CaddyMemoryRequest int    `json:"caddy_memory_request"`

	// Mail proxy configuration
	EnableMailProxy    bool   `json:"enable_mail_proxy"`
	NginxReplicas      int    `json:"nginx_replicas"`
	NginxVersion       string `json:"nginx_version"`
	MailPorts          []int  `json:"mail_ports"`
	MailBackend        string `json:"mail_backend"`
	NginxCPURequest    int    `json:"nginx_cpu_request"`
	NginxMemoryRequest int    `json:"nginx_memory_request"`

	// External services
	ExternalServices []ExternalService `json:"external_services"`

	// Service addresses
	ConsulAddress string `json:"consul_address"` // Consul address for Nomad integration
}

// ExternalService represents an external service to register in Consul
type ExternalService struct {
	Name    string   `json:"name"`
	Address string   `json:"address"`
	Port    int      `json:"port"`
	Tags    []string `json:"tags"`
}

// GetDefaultNomadConsulConfig returns default configuration
func GetDefaultNomadConsulConfig() *NomadConsulConfig {
	return &NomadConsulConfig{
		CloudDeploy: false,
		ClusterName: "nomad-consul-cluster",
		ServerType:  "cx21",
		Location:    "nbg1",
		NodeCount:   3,
		ServerCount: 3,
		Datacenter:  "dc1",
		Region:      "global",

		CaddyReplicas:      2,
		CaddyVersion:       "2.7-alpine",
		CaddyAdminEnabled:  true,
		CaddyCPURequest:    200,
		CaddyMemoryRequest: 256,

		EnableMailProxy:    false,
		NginxReplicas:      1,
		NginxVersion:       "1.24-alpine",
		MailPorts:          []int{25, 587, 465, 110, 995, 143, 993, 4190},
		MailBackend:        "stalwart-mail",
		NginxCPURequest:    100,
		NginxMemoryRequest: 128,

		ExternalServices: []ExternalService{},
		ConsulAddress:    fmt.Sprintf("%s:8500", shared.GetInternalHostname()),
	}
}
