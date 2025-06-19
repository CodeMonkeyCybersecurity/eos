// pkg/terraform/templates.go

package terraform

const K3sHetznerTemplate = `
terraform {
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.0"
    }
  }
}

provider "hcloud" {
  token = var.hcloud_token
}

variable "hcloud_token" {
  description = "Hetzner Cloud API Token"
  type        = string
  sensitive   = true
}

variable "server_name" {
  description = "Name of the K3s server"
  type        = string
  default     = "{{.ServerName}}"
}

variable "server_type" {
  description = "Server type for K3s node"
  type        = string
  default     = "{{.ServerType}}"
}

variable "location" {
  description = "Location for the server"
  type        = string
  default     = "{{.Location}}"
}

variable "ssh_key_name" {
  description = "SSH key name in Hetzner Cloud"
  type        = string
  default     = "{{.SSHKeyName}}"
}

variable "k3s_role" {
  description = "K3s role (server or agent)"
  type        = string
  default     = "{{.K3sRole}}"
}

variable "k3s_server_url" {
  description = "K3s server URL for agent nodes"
  type        = string
  default     = "{{.K3sServerURL}}"
}

variable "k3s_token" {
  description = "K3s cluster token"
  type        = string
  sensitive   = true
  default     = "{{.K3sToken}}"
}

data "hcloud_ssh_key" "key" {
  name = var.ssh_key_name
}

resource "hcloud_server" "k3s_node" {
  name        = var.server_name
  image       = "ubuntu-22.04"
  server_type = var.server_type
  location    = var.location
  ssh_keys    = [data.hcloud_ssh_key.key.id]

  user_data = templatefile("${path.module}/k3s-cloud-init.yaml", {
    k3s_role       = var.k3s_role
    k3s_server_url = var.k3s_server_url
    k3s_token      = var.k3s_token
  })

  labels = {
    type = "k3s"
    role = var.k3s_role
  }
}

resource "hcloud_firewall" "k3s" {
  name = "${var.server_name}-k3s-firewall"
  
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
    source_ips = ["0.0.0.0/0", "::/0"]
  }
}

resource "hcloud_firewall_attachment" "k3s" {
  firewall_id = hcloud_firewall.k3s.id
  server_ids  = [hcloud_server.k3s_node.id]
}

output "server_ip" {
  value = hcloud_server.k3s_node.ipv4_address
}

output "server_ipv6" {
  value = hcloud_server.k3s_node.ipv6_address
}

output "server_id" {
  value = hcloud_server.k3s_node.id
}
`

const K3sCloudInitTemplate = `#cloud-config
package_update: true
package_upgrade: true

packages:
  - curl
  - wget
  - apt-transport-https
  - ca-certificates
  - gnupg
  - lsb-release

runcmd:
  - |
    {{if eq .K3sRole "server"}}
    curl -sfL https://get.k3s.io | sh -s - server --tls-san $(hostname -I | awk '{print $1}')
    {{else}}
    export K3S_URL={{.K3sServerURL}}
    export K3S_TOKEN={{.K3sToken}}
    curl -sfL https://get.k3s.io | sh -s -
    {{end}}
  - systemctl enable k3s{{if eq .K3sRole "agent"}}-agent{{end}}
  - systemctl start k3s{{if eq .K3sRole "agent"}}-agent{{end}}

write_files:
  - path: /etc/systemd/system/k3s-status.service
    content: |
      [Unit]
      Description=K3s Status Logger
      After=k3s.service
      
      [Service]
      Type=oneshot
      ExecStart=/bin/bash -c 'systemctl is-active k3s && echo "K3s is running" || echo "K3s failed to start"'
      
      [Install]
      WantedBy=multi-user.target
`

const DockerComposeTemplate = `
terraform {
  required_providers {
    docker = {
      source  = "kreuzwerker/docker"
      version = "~> 3.0"
    }
    {{if .UseHetzner}}
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.0"
    }
    {{end}}
  }
}

provider "docker" {
  {{if .RemoteHost}}
  host = "{{.RemoteHost}}"
  {{end}}
}

{{if .UseHetzner}}
provider "hcloud" {
  token = var.hcloud_token
}

variable "hcloud_token" {
  description = "Hetzner Cloud API Token"
  type        = string
  sensitive   = true
}
{{end}}

variable "compose_file" {
  description = "Path to docker-compose.yml file"
  type        = string
  default     = "{{.ComposeFile}}"
}

variable "project_name" {
  description = "Docker Compose project name"
  type        = string
  default     = "{{.ProjectName}}"
}

{{range .Services}}
resource "docker_image" "{{.Name}}" {
  name = "{{.Image}}"
  {{if .PullTriggers}}
  pull_triggers = {{.PullTriggers}}
  {{end}}
}

resource "docker_container" "{{.Name}}" {
  name  = "{{.ProjectName}}_{{.Name}}"
  image = docker_image.{{.Name}}.image_id
  
  {{range .Ports}}
  ports {
    internal = {{.Internal}}
    external = {{.External}}
    protocol = "{{.Protocol}}"
  }
  {{end}}
  
  {{range .Volumes}}
  volumes {
    host_path      = "{{.HostPath}}"
    container_path = "{{.ContainerPath}}"
    {{if .ReadOnly}}read_only = true{{end}}
  }
  {{end}}
  
  {{range .EnvVars}}
  env = ["{{.Key}}={{.Value}}"]
  {{end}}
  
  {{if .Networks}}
  networks_advanced {
    {{range .Networks}}
    name = "{{.}}"
    {{end}}
  }
  {{end}}
  
  restart = "{{.RestartPolicy}}"
  
  {{if .HealthCheck}}
  healthcheck {
    test         = {{.HealthCheck.Test}}
    interval     = "{{.HealthCheck.Interval}}"
    timeout      = "{{.HealthCheck.Timeout}}"
    retries      = {{.HealthCheck.Retries}}
    start_period = "{{.HealthCheck.StartPeriod}}"
  }
  {{end}}
}
{{end}}

{{range .Networks}}
resource "docker_network" "{{.Name}}" {
  name = "{{.ProjectName}}_{{.Name}}"
  {{if .Driver}}driver = "{{.Driver}}"{{end}}
  {{if .Subnet}}
  ipam_config {
    subnet = "{{.Subnet}}"
  }
  {{end}}
}
{{end}}

{{range .Volumes}}
resource "docker_volume" "{{.Name}}" {
  name = "{{.ProjectName}}_{{.Name}}"
  {{if .Driver}}driver = "{{.Driver}}"{{end}}
}
{{end}}

output "container_ips" {
  value = {
    {{range .Services}}
    {{.Name}} = docker_container.{{.Name}}.network_data[0].ip_address
    {{end}}
  }
}
`

const HetznerInfraTemplate = `
terraform {
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = "~> 1.0"
    }
  }
}

provider "hcloud" {
  token = var.hcloud_token
}

variable "hcloud_token" {
  description = "Hetzner Cloud API Token"
  type        = string
  sensitive   = true
}

variable "project_name" {
  description = "Project name prefix"
  type        = string
  default     = "{{.ProjectName}}"
}

variable "ssh_key_name" {
  description = "SSH key name in Hetzner Cloud"
  type        = string
  default     = "{{.SSHKeyName}}"
}

{{range .Servers}}
resource "hcloud_server" "{{.Name}}" {
  name        = "${var.project_name}-{{.Name}}"
  image       = "{{.Image}}"
  server_type = "{{.Type}}"
  location    = "{{.Location}}"
  ssh_keys    = [data.hcloud_ssh_key.key.id]
  
  {{if .UserData}}
  user_data = file("{{.UserData}}")
  {{end}}
  
  labels = {
    project = var.project_name
    role    = "{{.Role}}"
    {{range $k, $v := .Labels}}
    {{$k}} = "{{$v}}"
    {{end}}
  }
}
{{end}}

{{range .Networks}}
resource "hcloud_network" "{{.Name}}" {
  name     = "${var.project_name}-{{.Name}}"
  ip_range = "{{.IPRange}}"
  
  labels = {
    project = var.project_name
  }
}

resource "hcloud_network_subnet" "{{.Name}}" {
  type         = "cloud"
  network_id   = hcloud_network.{{.Name}}.id
  network_zone = "{{.Zone}}"
  ip_range     = "{{.SubnetRange}}"
}
{{end}}

{{range .LoadBalancers}}
resource "hcloud_load_balancer" "{{.Name}}" {
  name               = "${var.project_name}-{{.Name}}"
  load_balancer_type = "{{.Type}}"
  location           = "{{.Location}}"
  
  labels = {
    project = var.project_name
  }
}

{{range .Services}}
resource "hcloud_load_balancer_service" "{{.Name}}" {
  load_balancer_id = hcloud_load_balancer.{{$.Name}}.id
  protocol         = "{{.Protocol}}"
  listen_port      = {{.ListenPort}}
  destination_port = {{.DestinationPort}}
  
  {{if .HealthCheck}}
  health_check {
    protocol = "{{.HealthCheck.Protocol}}"
    port     = {{.HealthCheck.Port}}
    interval = {{.HealthCheck.Interval}}
    timeout  = {{.HealthCheck.Timeout}}
    retries  = {{.HealthCheck.Retries}}
    {{if .HealthCheck.HTTP}}
    http {
      path         = "{{.HealthCheck.HTTP.Path}}"
      status_codes = {{.HealthCheck.HTTP.StatusCodes}}
    }
    {{end}}
  }
  {{end}}
}
{{end}}
{{end}}

data "hcloud_ssh_key" "key" {
  name = var.ssh_key_name
}

{{range .Firewalls}}
resource "hcloud_firewall" "{{.Name}}" {
  name = "${var.project_name}-{{.Name}}"
  
  {{range .Rules}}
  rule {
    direction = "{{.Direction}}"
    port      = "{{.Port}}"
    protocol  = "{{.Protocol}}"
    source_ips = {{.SourceIPs}}
  }
  {{end}}
  
  labels = {
    project = var.project_name
  }
}
{{end}}

output "server_ips" {
  value = {
    {{range .Servers}}
    {{.Name}} = hcloud_server.{{.Name}}.ipv4_address
    {{end}}
  }
}

output "load_balancer_ips" {
  value = {
    {{range .LoadBalancers}}
    {{.Name}} = hcloud_load_balancer.{{.Name}}.ipv4
    {{end}}
  }
}
`
