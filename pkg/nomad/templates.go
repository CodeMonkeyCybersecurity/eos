// pkg/nomad/templates.go
package nomad

// NomadJobTemplate contains Nomad job specification templates
// These templates replace K3s/Kubernetes deployments with Nomad equivalents

// CaddyIngressJobTemplate replaces K3s Caddy deployment with Nomad job
const CaddyIngressJobTemplate = `
job "caddy-ingress" {
  region      = "{{.Region}}"
  datacenters = ["{{.Datacenter}}"]
  type        = "service"
  priority    = 75

  group "caddy" {
    count = {{.CaddyReplicas}}

    network {
      port "http" {
        static = 80
      }
      port "https" {
        static = 443
      }
      {{if .CaddyAdminEnabled}}
      port "admin" {
        static = 2019
      }
      {{end}}
    }

    service {
      name = "caddy-ingress"
      port = "http"
      
      tags = [
        "ingress",
        "http",
        "reverse-proxy",
        "traefik.enable=true",
        "traefik.http.routers.caddy.rule=Host(` + "`{{.Domain}}`" + `)"
      ]

      check {
        type     = "http"
        path     = "/health"
        interval = "30s"
        timeout  = "5s"
      }
    }

    service {
      name = "caddy-ingress-https"
      port = "https"
      
      tags = [
        "ingress",
        "https",
        "reverse-proxy",
        "ssl"
      ]

      check {
        type     = "tcp"
        interval = "30s"
        timeout  = "5s"
      }
    }

    volume "caddy-data" {
      type      = "host"
      read_only = false
      source    = "caddy-data"
    }

    task "caddy" {
      driver = "docker"

      config {
        image = "caddy:{{.CaddyVersion}}"
        ports = ["http", "https"{{if .CaddyAdminEnabled}}, "admin"{{end}}]
        
        volumes = [
          "local/Caddyfile:/etc/caddy/Caddyfile",
          "caddy-data:/data",
          "local/config:/config"
        ]
      }

      template {
        data = <<EOH
# Caddyfile for Nomad Ingress
{{.Domain}} {
    # Health check endpoint
    handle /health {
        respond "OK" 200
    }
    
    # Proxy to backend services via Consul
    reverse_proxy /* {
        to {{ range $svc := .BackendServices }}{{$svc.Address}}:{{$svc.Port}} {{ end }}
        health_uri /health
        health_interval 30s
        lb_policy round_robin
    }
    
    # Enable automatic HTTPS
    tls {
        protocols tls1.2 tls1.3
    }
    
    # Security headers
    header {
        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        X-XSS-Protection "1; mode=block"
        Referrer-Policy "strict-origin-when-cross-origin"
        -Server
    }
    
    # Logging
    log {
        output file /var/log/caddy/access.log
        format console
    }
}

{{if .CaddyAdminEnabled}}
# Admin API
:2019 {
    metrics /metrics
    handle /config/* {
        admin
    }
}
{{end}}
EOH
        destination = "local/Caddyfile"
      }

      resources {
        cpu    = {{.CaddyCPURequest}}
        memory = {{.CaddyMemoryRequest}}
      }

      env {
        CADDY_ADMIN = "{{if .CaddyAdminEnabled}}0.0.0.0:2019{{else}}off{{end}}"
      }
    }
  }
}
`

// NginxMailProxyJobTemplate replaces K3s Nginx mail proxy with Nomad job
const NginxMailProxyJobTemplate = `
job "nginx-mail-proxy" {
  region      = "{{.Region}}"
  datacenters = ["{{.Datacenter}}"]
  type        = "service"
  priority    = 70

  group "nginx" {
    count = {{.NginxReplicas}}

    network {
      {{range .MailPorts}}
      port "mail-{{.}}" {
        static = {{.}}
      }
      {{end}}
      port "auth" {
        static = 8080
      }
    }

    service {
      name = "nginx-mail-proxy"
      port = "auth"
      
      tags = [
        "mail-proxy",
        "nginx",
        "smtp",
        "imap",
        "pop3"
      ]

      check {
        type     = "http"
        path     = "/health"
        interval = "30s"
        timeout  = "5s"
      }
    }

    {{range .MailPorts}}
    service {
      name = "mail-{{.}}"
      port = "mail-{{.}}"
      
      tags = [
        "mail",
        "port-{{.}}"
      ]

      check {
        type     = "tcp"
        interval = "30s"
        timeout  = "5s"
      }
    }
    {{end}}

    task "nginx" {
      driver = "docker"

      config {
        image = "nginx:{{.NginxVersion}}"
        ports = [{{range $i, $port := .MailPorts}}{{if $i}}, {{end}}"mail-{{$port}}"{{end}}, "auth"]
        
        volumes = [
          "local/nginx.conf:/etc/nginx/nginx.conf",
          "local/certs:/etc/nginx/certs:ro"
        ]
      }

      template {
        data = <<EOH
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
    server_name {{.Domain}};
    auth_http http://{{.MailBackend}}:8080/auth;
    
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
        server {{.MailBackend}}:8080;
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
EOH
        destination = "local/nginx.conf"
      }

      resources {
        cpu    = {{.NginxCPURequest}}
        memory = {{.NginxMemoryRequest}}
      }
    }
  }
}
`

// ConsulConnectSidecarTemplate for service mesh integration
const ConsulConnectSidecarTemplate = `
    sidecar_service {
      proxy {
        upstreams {
          destination_name = "{{.UpstreamService}}"
          local_bind_port  = {{.UpstreamPort}}
        }
      }
    }
`

// NomadServiceDeploymentTemplate replaces K3s service deployments
const NomadServiceDeploymentTemplate = `
job "{{.ServiceName}}" {
  region      = "{{.Region}}"
  datacenters = ["{{.Datacenter}}"]
  type        = "{{.JobType}}"
  priority    = {{.Priority}}

  {{if .Constraints}}
  {{range .Constraints}}
  constraint {
    attribute = "{{.Attribute}}"
    operator  = "{{.Operator}}"
    value     = "{{.Value}}"
  }
  {{end}}
  {{end}}

  group "{{.ServiceName}}" {
    count = {{.Replicas}}

    {{if .Networks}}
    network {
      {{range .Networks}}
      port "{{.Name}}" {
        {{if .Static}}static = {{.Port}}{{else}}to = {{.Port}}{{end}}
      }
      {{end}}
    }
    {{end}}

    {{if .Volumes}}
    {{range .Volumes}}
    volume "{{.Name}}" {
      type      = "{{.Type}}"
      read_only = {{.ReadOnly}}
      source    = "{{.Source}}"
    }
    {{end}}
    {{end}}

    service {
      name = "{{.ServiceName}}"
      {{if .ServicePort}}port = "{{.ServicePort}}"{{end}}
      
      tags = [
        {{range $i, $tag := .ServiceTags}}{{if $i}}, {{end}}"{{$tag}}"{{end}}
      ]

      {{if .HealthCheck}}
      check {
        type     = "{{.HealthCheck.Type}}"
        {{if eq .HealthCheck.Type "http"}}path     = "{{.HealthCheck.Path}}"{{end}}
        interval = "{{.HealthCheck.Interval}}"
        timeout  = "{{.HealthCheck.Timeout}}"
      }
      {{end}}

      {{if .ConsulConnect}}
      connect {
        sidecar_service {}
      }
      {{end}}
    }

    {{if .RestartPolicy}}
    restart {
      attempts = {{.RestartPolicy.Attempts}}
      interval = "{{.RestartPolicy.Interval}}"
      delay    = "{{.RestartPolicy.Delay}}"
      mode     = "{{.RestartPolicy.Mode}}"
    }
    {{end}}

    task "{{.ServiceName}}" {
      driver = "{{.Driver}}"

      config {
        {{if eq .Driver "docker"}}
        image = "{{.Image}}"
        {{if .Ports}}ports = [{{range $i, $port := .Ports}}{{if $i}}, {{end}}"{{$port}}"{{end}}]{{end}}
        {{if .DockerVolumes}}
        volumes = [
          {{range $i, $vol := .DockerVolumes}}{{if $i}}, {{end}}"{{$vol}}"{{end}}
        ]
        {{end}}
        {{if .Command}}command = "{{.Command}}"{{end}}
        {{if .Args}}args = [{{range $i, $arg := .Args}}{{if $i}}, {{end}}"{{$arg}}"{{end}}]{{end}}
        {{end}}
      }

      {{if .EnvVars}}
      env {
        {{range $key, $value := .EnvVars}}
        {{$key}} = "{{$value}}"
        {{end}}
      }
      {{end}}

      {{if .Resources}}
      resources {
        cpu    = {{.Resources.CPU}}
        memory = {{.Resources.Memory}}
        {{if .Resources.Disk}}disk   = {{.Resources.Disk}}{{end}}
      }
      {{end}}

      {{if .Templates}}
      {{range .Templates}}
      template {
        data = <<EOH
{{.Data}}
EOH
        destination = "{{.Destination}}"
        {{if .ChangeMode}}change_mode = "{{.ChangeMode}}"{{end}}
        {{if .Perms}}perms = "{{.Perms}}"{{end}}
      }
      {{end}}
      {{end}}
    }
  }
}
`

// NomadClusterSetupTemplate for initial cluster bootstrap
const NomadClusterSetupTemplate = `
job "cluster-bootstrap" {
  region      = "{{.Region}}"
  datacenters = ["{{.Datacenter}}"]
  type        = "batch"
  priority    = 100

  group "bootstrap" {
    count = 1

    task "setup-cluster" {
      driver = "raw_exec"

      config {
        command = "/bin/bash"
        args    = ["local/bootstrap.sh"]
      }

      template {
        data = <<EOH
#!/bin/bash
set -euo pipefail

echo "Setting up Nomad cluster..."

# Wait for Nomad to be ready
while ! nomad status > /dev/null 2>&1; do
  echo "Waiting for Nomad to be ready..."
  sleep 5
done

# Initialize ACLs if enabled
{{if .EnableACL}}
if ! nomad acl bootstrap 2>/dev/null; then
  echo "ACL already bootstrapped or not ready"
fi
{{end}}

# Setup host volumes for persistent storage
{{range .HostVolumes}}
nomad operator inspect --node {{.NodeID}} || echo "Node {{.NodeID}} not found"
{{end}}

echo "Cluster bootstrap completed"
EOH
        destination = "local/bootstrap.sh"
        perms       = "755"
      }

      resources {
        cpu    = 100
        memory = 128
      }
    }
  }
}
`

// NomadVolumeHostConfig for persistent storage
const NomadVolumeHostConfig = `
client {
  host_volume "{{.VolumeName}}" {
    path      = "{{.HostPath}}"
    read_only = {{.ReadOnly}}
  }
}
`
