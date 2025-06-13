// pkg/terraform/k3s_caddy_nginx.go

package terraform

// K3s with Caddy + Nginx instead of Traefik
const K3sCaddyNginxTemplate = `
terraform {
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
    helm = {
      source  = "hashicorp/helm"
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

resource "hcloud_server" "k3s_master" {
  name        = "{{.ClusterName}}-master"
  image       = "ubuntu-22.04"
  server_type = "{{.ServerType}}"
  location    = "{{.Location}}"
  ssh_keys    = [data.hcloud_ssh_key.key.id]

  user_data = templatefile("${path.module}/k3s-cloud-init.yaml", {
    domain       = var.domain
    cluster_name = "{{.ClusterName}}"
  })

  labels = {
    type = "k3s-master"
    cluster = "{{.ClusterName}}"
  }
}

data "hcloud_ssh_key" "key" {
  name = var.ssh_key_name
}

# Firewall for K3s + HTTP/HTTPS + Mail
resource "hcloud_firewall" "k3s_cluster" {
  name = "{{.ClusterName}}-firewall"
  
  # SSH
  rule {
    direction = "in"
    port      = "22"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  # K3s API
  rule {
    direction = "in"
    port      = "6443"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  # HTTP/HTTPS (Caddy)
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

  # Mail ports (Nginx)
  {{range .MailPorts}}
  rule {
    direction = "in"
    port      = "{{.}}"
    protocol  = "tcp"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
  {{end}}
}

resource "hcloud_firewall_attachment" "k3s_cluster" {
  firewall_id = hcloud_firewall.k3s_cluster.id
  server_ids  = [hcloud_server.k3s_master.id]
}

# Load Balancer for external access
resource "hcloud_load_balancer" "k3s_lb" {
  name               = "{{.ClusterName}}-lb"
  load_balancer_type = "lb11"
  location           = "{{.Location}}"
}

resource "hcloud_load_balancer_target" "k3s_lb_target" {
  type             = "server"
  load_balancer_id = hcloud_load_balancer.k3s_lb.id
  server_id        = hcloud_server.k3s_master.id
}

# HTTP service
resource "hcloud_load_balancer_service" "http" {
  load_balancer_id = hcloud_load_balancer.k3s_lb.id
  protocol         = "http"
  listen_port      = 80
  destination_port = 80
}

# HTTPS service
resource "hcloud_load_balancer_service" "https" {
  load_balancer_id = hcloud_load_balancer.k3s_lb.id
  protocol         = "tcp"
  listen_port      = 443
  destination_port = 443
}

output "server_ip" {
  value = hcloud_server.k3s_master.ipv4_address
}

output "load_balancer_ip" {
  value = hcloud_load_balancer.k3s_lb.ipv4
}
{{end}}

# Kubernetes provider configuration
provider "kubernetes" {
  {{if .CloudDeploy}}
  host = "https://${hcloud_server.k3s_master.ipv4_address}:6443"
  {{else}}
  config_path = "~/.kube/config"
  {{end}}
}

provider "helm" {
  kubernetes {
    {{if .CloudDeploy}}
    host = "https://${hcloud_server.k3s_master.ipv4_address}:6443"
    {{else}}
    config_path = "~/.kube/config"
    {{end}}
  }
}

# Create namespace for our ingress system
resource "kubernetes_namespace" "ingress_system" {
  metadata {
    name = "ingress-system"
    labels = {
      "app.kubernetes.io/name" = "ingress-system"
    }
  }
}

# ConfigMap for Caddy configuration
resource "kubernetes_config_map" "caddy_config" {
  metadata {
    name      = "caddy-config"
    namespace = kubernetes_namespace.ingress_system.metadata[0].name
  }

  data = {
    "Caddyfile" = templatefile("${path.module}/config/Caddyfile.tpl", {
      domain = var.domain
      enable_admin = var.caddy_admin_enabled
    })
  }
}

# ConfigMap for Nginx mail proxy configuration  
resource "kubernetes_config_map" "nginx_mail_config" {
  metadata {
    name      = "nginx-mail-config"
    namespace = kubernetes_namespace.ingress_system.metadata[0].name
  }

  data = {
    "nginx.conf" = templatefile("${path.module}/config/nginx-mail.conf.tpl", {
      upstream_host = "{{.MailBackend}}"
      domain = var.domain
    })
    "stream.conf" = file("${path.module}/config/nginx-stream.conf")
  }
}

# Caddy Deployment (HTTP/HTTPS Ingress)
resource "kubernetes_deployment" "caddy_ingress" {
  metadata {
    name      = "caddy-ingress"
    namespace = kubernetes_namespace.ingress_system.metadata[0].name
    labels = {
      app = "caddy-ingress"
    }
  }

  spec {
    replicas = {{.CaddyReplicas}}

    selector {
      match_labels = {
        app = "caddy-ingress"
      }
    }

    template {
      metadata {
        labels = {
          app = "caddy-ingress"
        }
      }

      spec {
        container {
          name  = "caddy"
          image = "caddy:{{.CaddyVersion}}"

          port {
            name           = "http"
            container_port = 80
          }

          port {
            name           = "https"
            container_port = 443
          }

          {{if .CaddyAdminEnabled}}
          port {
            name           = "admin"
            container_port = 2019
          }
          {{end}}

          volume_mount {
            name       = "caddy-config"
            mount_path = "/etc/caddy"
          }

          volume_mount {
            name       = "caddy-data"
            mount_path = "/data"
          }

          volume_mount {
            name       = "caddy-config-cache"
            mount_path = "/config"
          }

          env {
            name  = "CADDY_ADMIN"
            value = "{{if .CaddyAdminEnabled}}0.0.0.0:2019{{else}}off{{end}}"
          }

          resources {
            requests = {
              memory = "{{.CaddyMemoryRequest}}"
              cpu    = "{{.CaddyCPURequest}}"
            }
            limits = {
              memory = "{{.CaddyMemoryLimit}}"
              cpu    = "{{.CaddyCPULimit}}"
            }
          }

          liveness_probe {
            http_get {
              path = "/health"
              port = "http"
            }
            initial_delay_seconds = 30
            period_seconds        = 10
          }

          readiness_probe {
            http_get {
              path = "/health"
              port = "http"
            }
            initial_delay_seconds = 5
            period_seconds        = 5
          }
        }

        volume {
          name = "caddy-config"
          config_map {
            name = kubernetes_config_map.caddy_config.metadata[0].name
          }
        }

        volume {
          name = "caddy-data"
          persistent_volume_claim {
            claim_name = kubernetes_persistent_volume_claim.caddy_data.metadata[0].name
          }
        }

        volume {
          name = "caddy-config-cache"
          empty_dir {}
        }
      }
    }
  }
}

# Nginx Mail Proxy Deployment
resource "kubernetes_deployment" "nginx_mail_proxy" {
  metadata {
    name      = "nginx-mail-proxy"
    namespace = kubernetes_namespace.ingress_system.metadata[0].name
    labels = {
      app = "nginx-mail-proxy"
    }
  }

  spec {
    replicas = {{.NginxReplicas}}

    selector {
      match_labels = {
        app = "nginx-mail-proxy"
      }
    }

    template {
      metadata {
        labels = {
          app = "nginx-mail-proxy"
        }
      }

      spec {
        container {
          name  = "nginx"
          image = "nginx:{{.NginxVersion}}"

          # Mail ports
          {{range .MailPorts}}
          port {
            name           = "mail-{{.}}"
            container_port = {{.}}
            protocol       = "TCP"
          }
          {{end}}

          volume_mount {
            name       = "nginx-mail-config"
            mount_path = "/etc/nginx"
          }

          volume_mount {
            name       = "nginx-logs"
            mount_path = "/var/log/nginx"
          }

          resources {
            requests = {
              memory = "{{.NginxMemoryRequest}}"
              cpu    = "{{.NginxCPURequest}}"
            }
            limits = {
              memory = "{{.NginxMemoryLimit}}"
              cpu    = "{{.NginxCPULimit}}"
            }
          }
        }

        volume {
          name = "nginx-mail-config"
          config_map {
            name = kubernetes_config_map.nginx_mail_config.metadata[0].name
          }
        }

        volume {
          name = "nginx-logs"
          empty_dir {}
        }
      }
    }
  }
}

# PVCs for persistent storage
resource "kubernetes_persistent_volume_claim" "caddy_data" {
  metadata {
    name      = "caddy-data"
    namespace = kubernetes_namespace.ingress_system.metadata[0].name
  }
  spec {
    access_modes = ["ReadWriteOnce"]
    resources {
      requests = {
        storage = "{{.CaddyStorageSize}}"
      }
    }
  }
}

# Services
resource "kubernetes_service" "caddy_ingress" {
  metadata {
    name      = "caddy-ingress"
    namespace = kubernetes_namespace.ingress_system.metadata[0].name
    annotations = {
      "metallb.universe.tf/allow-shared-ip" = "ingress"
    }
  }

  spec {
    type = "LoadBalancer"
    
    selector = {
      app = "caddy-ingress"
    }

    port {
      name        = "http"
      port        = 80
      target_port = 80
      protocol    = "TCP"
    }

    port {
      name        = "https"
      port        = 443
      target_port = 443
      protocol    = "TCP"
    }

    {{if .CaddyAdminEnabled}}
    port {
      name        = "admin"
      port        = 2019
      target_port = 2019
      protocol    = "TCP"
    }
    {{end}}
  }
}

resource "kubernetes_service" "nginx_mail_proxy" {
  metadata {
    name      = "nginx-mail-proxy"
    namespace = kubernetes_namespace.ingress_system.metadata[0].name
    annotations = {
      "metallb.universe.tf/allow-shared-ip" = "mail"
    }
  }

  spec {
    type = "LoadBalancer"
    
    selector = {
      app = "nginx-mail-proxy"
    }

    {{range .MailPorts}}
    port {
      name        = "mail-{{.}}"
      port        = {{.}}
      target_port = {{.}}
      protocol    = "TCP"
    }
    {{end}}
  }
}

# Variables
variable "domain" {
  description = "Primary domain for the cluster"
  type        = string
}

variable "caddy_admin_enabled" {
  description = "Enable Caddy admin API"
  type        = bool
  default     = true
}

# Outputs
output "caddy_service_ip" {
  value = kubernetes_service.caddy_ingress.status[0].load_balancer[0].ingress[0].ip
}

output "nginx_mail_service_ip" {
  value = kubernetes_service.nginx_mail_proxy.status[0].load_balancer[0].ingress[0].ip
}

output "cluster_info" {
  value = {
    caddy_replicas = {{.CaddyReplicas}}
    nginx_replicas = {{.NginxReplicas}}
    namespace = kubernetes_namespace.ingress_system.metadata[0].name
  }
}
`

// K3s Cloud Init Template for Caddy + Nginx setup
const K3sCaddyNginxCloudInit = `#cloud-config
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
  # Install K3s without Traefik (we'll use Caddy + Nginx instead)
  - |
    curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="server --disable traefik --disable servicelb" sh -s -
  
  # Install MetalLB for LoadBalancer services
  - |
    kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.13.7/config/manifests/metallb-native.yaml
    
  # Wait for MetalLB to be ready
  - sleep 30
  
  # Configure MetalLB IP pool (adjust range as needed)
  - |
    cat <<EOF | kubectl apply -f -
    apiVersion: metallb.io/v1beta1
    kind: IPAddressPool
    metadata:
      name: default-pool
      namespace: metallb-system
    spec:
      addresses:
      - 10.0.0.100-10.0.0.200
    ---
    apiVersion: metallb.io/v1beta1
    kind: L2Advertisement
    metadata:
      name: default
      namespace: metallb-system
    spec:
      ipAddressPools:
      - default-pool
    EOF

  # Enable and start K3s
  - systemctl enable k3s
  - systemctl start k3s
  
  # Setup kubectl for ubuntu user
  - mkdir -p /home/ubuntu/.kube
  - cp /etc/rancher/k3s/k3s.yaml /home/ubuntu/.kube/config
  - chown ubuntu:ubuntu /home/ubuntu/.kube/config
  - chmod 600 /home/ubuntu/.kube/config

write_files:
  - path: /opt/k3s-status.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      echo "Checking K3s status..."
      kubectl get nodes
      kubectl get pods -A
      echo "K3s setup complete!"
`

// Configuration template files
const CaddyfileTemplate = `
# Caddyfile for K3s Ingress
{{.domain}} {
    # Health check endpoint
    handle /health {
        respond "OK" 200
    }
    
    # Proxy to Kubernetes services
    reverse_proxy /* {
        to http://backend-service.default.svc.cluster.local:80
        health_uri /health
        health_interval 30s
    }
    
    # Enable automatic HTTPS
    tls {
        protocols tls1.2 tls1.3
    }
    
    # Security headers
    header {
        # Security headers
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        X-XSS-Protection "1; mode=block"
        Referrer-Policy "strict-origin-when-cross-origin"
        
        # Remove server info
        -Server
    }
    
    # Logging
    log {
        output file /var/log/caddy/access.log
        format console
    }
}

{{if .enable_admin}}
# Admin API (internal only)
:2019 {
    metrics /metrics
}
{{end}}
`

const NginxMailConfigTemplate = `
# Nginx Mail Proxy Configuration
user  nginx;
worker_processes  auto;

error_log  /var/log/nginx/error.log notice;
pid        /var/run/nginx.pid;

events {
    worker_connections  1024;
}

# Mail proxy configuration
mail {
    server_name {{.domain}};
    auth_http http://{{.upstream_host}}:8080/auth;
    
    proxy_pass_error_message on;
    proxy_timeout 1m;
    proxy_connect_timeout 15s;
    
    # SSL configuration
    ssl_certificate /etc/nginx/certs/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    
    # SMTP
    server {
        listen 25;
        protocol smtp;
        smtp_auth login plain;
        xclient off;
    }
    
    # Submission
    server {
        listen 587;
        protocol smtp;
        smtp_auth login plain;
        starttls on;
        xclient off;
    }
    
    # Submission with SSL
    server {
        listen 465 ssl;
        protocol smtp;
        smtp_auth login plain;
        xclient off;
    }
    
    # IMAP
    server {
        listen 143;
        protocol imap;
        starttls on;
    }
    
    # IMAPS
    server {
        listen 993 ssl;
        protocol imap;
    }
    
    # POP3
    server {
        listen 110;
        protocol pop3;
        starttls on;
    }
    
    # POP3S
    server {
        listen 995 ssl;
        protocol pop3;
    }
    
    # Sieve
    server {
        listen 4190;
        protocol smtp;
        smtp_auth login plain;
        starttls on;
    }
}

# HTTP for health checks and auth
http {
    upstream auth_backend {
        server {{.upstream_host}}:8080;
    }
    
    server {
        listen 8080;
        
        location /auth {
            proxy_pass http://auth_backend;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_set_header X-Original-URI $request_uri;
        }
        
        location /health {
            return 200 "OK\n";
            add_header Content-Type text/plain;
        }
    }
}
`

type K3sCaddyNginxConfig struct {
	CloudDeploy          bool
	ClusterName          string
	ServerType           string
	Location             string
	Domain               string
	CaddyVersion         string
	NginxVersion         string
	CaddyReplicas        int
	NginxReplicas        int
	CaddyAdminEnabled    bool
	CaddyStorageSize     string
	CaddyMemoryRequest   string
	CaddyCPURequest      string
	CaddyMemoryLimit     string
	CaddyCPULimit        string
	NginxMemoryRequest   string
	NginxCPURequest      string
	NginxMemoryLimit     string
	NginxCPULimit        string
	MailPorts            []int
	MailBackend          string
}