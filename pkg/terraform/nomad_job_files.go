// pkg/terraform/nomad_job_files.go
package terraform

// CaddyIngressNomadJob is the Terraform-generated Nomad job for Caddy ingress
const CaddyIngressNomadJob = `
job "caddy-ingress" {
  region      = "${region}"
  datacenters = ["${datacenter}"]
  type        = "service"
  priority    = 75

  group "caddy" {
    count = ${replicas}

    network {
      port "http" {
        static = 80
      }
      port "https" {
        static = 443
      }
      %{ if admin_enabled }
      port "admin" {
        static = 2019
      }
      %{ endif }
    }

    service {
      name = "caddy-ingress"
      port = "http"
      
      tags = [
        "ingress",
        "http",
        "reverse-proxy",
        "traefik.enable=true",
        "traefik.http.routers.caddy.rule=Host(` + "`" + `${domain}` + "`" + `)"
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
        image = "caddy:${version}"
        ports = ["http", "https"%{ if admin_enabled }, "admin"%{ endif }]
        
        volumes = [
          "local/Caddyfile:/etc/caddy/Caddyfile",
          "caddy-data:/data",
          "local/config:/config"
        ]
      }

      template {
        data = <<EOH
# Caddyfile for Nomad Ingress
${domain} {
    # Health check endpoint
    handle /health {
        respond "OK" 200
    }
    
    # Proxy to backend services via Consul
    reverse_proxy /* {
        to {{ range service "backend-service" }}{{ .Address }}:{{ .Port }} {{ end }}
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

%{ if admin_enabled }
# Admin API
:2019 {
    metrics /metrics
    handle /config/* {
        admin
    }
}
%{ endif }
EOH
        destination = "local/Caddyfile"
      }

      resources {
        cpu    = ${cpu_request}
        memory = ${memory_request}
      }

      env {
        CADDY_ADMIN = "%{ if admin_enabled }0.0.0.0:2019%{ else }off%{ endif }"
      }
    }
  }
}
`

// NginxMailNomadJob is the Terraform-generated Nomad job for Nginx mail proxy
const NginxMailNomadJob = `
job "nginx-mail-proxy" {
  region      = "${region}"
  datacenters = ["${datacenter}"]
  type        = "service"
  priority    = 70

  group "nginx" {
    count = ${replicas}

    network {
      %{ for port in mail_ports }
      port "mail-${port}" {
        static = ${port}
      }
      %{ endfor }
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

    %{ for port in mail_ports }
    service {
      name = "mail-${port}"
      port = "mail-${port}"
      
      tags = [
        "mail",
        "port-${port}"
      ]

      check {
        type     = "tcp"
        interval = "30s"
        timeout  = "5s"
      }
    }
    %{ endfor }

    task "nginx" {
      driver = "docker"

      config {
        image = "nginx:${version}"
        ports = [%{ for port in mail_ports }"mail-${port}", %{ endfor }"auth"]
        
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
    server_name ${domain};
    auth_http http://${mail_backend}:8080/auth;
    
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
        server ${mail_backend}:8080;
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
        cpu    = ${cpu_request}
        memory = ${memory_request}
      }
    }
  }
}
`

// BasicServiceNomadJob is a template for migrating basic services from K3s
const BasicServiceNomadJob = `
job "${service_name}" {
  region      = "${region}"
  datacenters = ["${datacenter}"]
  type        = "service"
  priority    = 50

  group "${service_name}" {
    count = ${replicas}

    network {
      %{ for port in ports }
      port "port-${port}" {
        to = ${port}
      }
      %{ endfor }
    }

    service {
      name = "${service_name}"
      port = "port-${primary_port}"
      
      tags = [
        "migrated-from-k3s",
        "version-${version}",
        %{ for tag in tags }"${tag}",
        %{ endfor }
      ]

      check {
        type     = "http"
        path     = "${health_path}"
        interval = "30s"
        timeout  = "5s"
      }
    }

    task "${service_name}" {
      driver = "docker"

      config {
        image = "${image}"
        ports = [%{ for port in ports }"port-${port}", %{ endfor }]
        %{ if volumes != "" }
        volumes = [
          ${volumes}
        ]
        %{ endif }
      }

      %{ if env_vars != "" }
      env {
        ${env_vars}
      }
      %{ endif }

      resources {
        cpu    = ${cpu_request}
        memory = ${memory_request}
      }
    }
  }
}
`