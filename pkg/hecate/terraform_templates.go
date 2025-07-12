package hecate

// TerraformTemplate is the main Terraform template for Hecate deployment
// Migrated from cmd/create/hecate_terraform.go HecateTerraformTemplate
const TerraformTemplate = `
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
  {{if .DockerHost}}
  host = "{{.DockerHost}}"
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

resource "hcloud_server" "hecate" {
  name        = "{{.ServerName}}"
  image       = "ubuntu-22.04"
  server_type = "{{.ServerType}}"
  location    = "{{.Location}}"
  ssh_keys    = [data.hcloud_ssh_key.key.id]

  user_data = templatefile("${path.module}/hecate-cloud-init.yaml", {
    domain = var.domain
  })

  labels = {
    type = "hecate"
    role = "mail-server"
  }
}

data "hcloud_ssh_key" "key" {
  name = var.ssh_key_name
}

resource "hcloud_firewall" "hecate" {
  name = "{{.ServerName}}-hecate-firewall"
  
  # SSH
  rule {
    direction = "in"
    port      = "22"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  # HTTP/HTTPS
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

  # Mail ports
  rule {
    direction = "in"
    port      = "25"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    port      = "587"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    port      = "465"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    port      = "110"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    port      = "995"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    port      = "143"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    port      = "993"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction = "in"
    port      = "4190"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
}

resource "hcloud_firewall_attachment" "hecate" {
  firewall_id = hcloud_firewall.hecate.id
  server_ids  = [hcloud_server.hecate.id]
}

variable "ssh_key_name" {
  description = "SSH key name in Hetzner Cloud"
  type        = string
}

variable "domain" {
  description = "Domain name for the mail server"
  type        = string
}

output "server_ip" {
  value = hcloud_server.hecate.ipv4_address
}
{{end}}

# Docker Networks
resource "docker_network" "hecate_net" {
  name = "hecate-net"
}

# Docker Volumes
resource "docker_volume" "stalwart_data" {
  name = "stalwart_data"
}

# Stalwart Mail Server
resource "docker_image" "stalwart" {
  name = "stalwartlabs/stalwart:latest"
}

resource "docker_container" "stalwart" {
  name  = "hecate-stalwart"
  image = docker_image.stalwart.image_id
  
  restart = "always"
  
  ports {
    internal = 8080
    external = 8080
    protocol = "tcp"
  }
  
  volumes {
    volume_name    = docker_volume.stalwart_data.name
    container_path = "/opt/stalwart"
  }
  
  networks_advanced {
    name = docker_network.hecate_net.name
  }
}

# Caddy
resource "docker_image" "caddy" {
  name = "caddy:latest"
}

resource "docker_container" "caddy" {
  name  = "hecate-caddy"
  image = docker_image.caddy.image_id
  
  restart = "always"
  
  ports {
    internal = 80
    external = 80
    protocol = "tcp"
  }
  
  ports {
    internal = 443
    external = 443
    protocol = "tcp"
  }
  
  volumes {
    host_path      = "./Caddyfile"
    container_path = "/etc/caddy/Caddyfile"
    read_only      = true
  }
  
  volumes {
    host_path      = "./certs"
    container_path = "/data/caddy/certs"
  }
  
  volumes {
    host_path      = "./logs/caddy"
    container_path = "/var/log/caddy"
  }
  
  volumes {
    host_path      = "./assets/error_pages"
    container_path = "/usr/share/nginx/html"
    read_only      = true
  }
  
  networks_advanced {
    name = docker_network.hecate_net.name
  }
}

# Nginx
resource "docker_image" "nginx" {
  name = "nginx:alpine"
}

resource "docker_container" "nginx" {
  name  = "hecate-nginx"
  image = docker_image.nginx.image_id
  
  restart = "always"
  
  # Mail ports
  ports {
    internal = 25
    external = 25
    protocol = "tcp"
  }
  
  ports {
    internal = 587
    external = 587
    protocol = "tcp"
  }
  
  ports {
    internal = 465
    external = 465
    protocol = "tcp"
  }
  
  ports {
    internal = 110
    external = 110
    protocol = "tcp"
  }
  
  ports {
    internal = 995
    external = 995
    protocol = "tcp"
  }
  
  ports {
    internal = 143
    external = 143
    protocol = "tcp"
  }
  
  ports {
    internal = 993
    external = 993
    protocol = "tcp"
  }
  
  ports {
    internal = 4190
    external = 4190
    protocol = "tcp"
  }
  
  volumes {
    host_path      = "./nginx.conf"
    container_path = "/etc/nginx/nginx.conf"
    read_only      = true
  }
  
  volumes {
    host_path      = "./logs"
    container_path = "/var/log/nginx"
  }
  
  volumes {
    host_path      = "./certs"
    container_path = "/opt/hecate/certs"
    read_only      = true
  }
  
  networks_advanced {
    name = docker_network.hecate_net.name
  }
}

output "container_ips" {
  value = {
    stalwart = docker_container.stalwart.network_data[0].ip_address
    caddy    = docker_container.caddy.network_data[0].ip_address
    nginx    = docker_container.nginx.network_data[0].ip_address
  }
}
`

// CloudInitTemplate is the cloud-init template for Hecate deployment
// Migrated from cmd/create/hecate_terraform.go HecateCloudInitTemplate
const CloudInitTemplate = `#cloud-config
package_update: true
package_upgrade: true

packages:
  - docker.io
  - docker-compose
  - curl
  - wget

runcmd:
  - systemctl enable docker
  - systemctl start docker
  - usermod -aG docker ubuntu
  - mkdir -p /opt/hecate
  - cd /opt/hecate
  - |
    cat > docker-compose.yml << 'EOF'
    # Your original docker-compose.yml content would go here
    # This is managed by Terraform instead
    EOF
  - docker compose up -d

write_files:
  - path: /opt/hecate/Caddyfile
    content: |
      # Caddyfile configuration
      {{.domain}} {
        reverse_proxy hecate-stalwart:8080
      }
`
