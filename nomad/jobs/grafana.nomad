# Grafana Nomad Job Template
# Managed by Eos - Do not edit manually

variable "admin_password" {
  type = string
  default = "admin"
  description = "Grafana admin password"
}

variable "port" {
  type = number
  default = 3000
  description = "Grafana HTTP port"
}

variable "datacenter" {
  type = string
  default = "dc1"
  description = "Nomad datacenter"
}

variable "data_path" {
  type = string
  default = "/opt/grafana/data"
  description = "Grafana data directory"
}

job "grafana" {
  datacenters = [var.datacenter]
  type = "service"
  
  group "grafana" {
    count = 1
    
    network {
      port "http" { 
        to = var.port
      }
    }
    
    volume "grafana_data" {
      type = "host"
      source = "grafana_data"
      read_only = false
    }
    
    task "grafana" {
      driver = "docker"
      
      config {
        image = "grafana/grafana:latest"
        ports = ["http"]
        
        volumes = [
          "local/grafana.ini:/etc/grafana/grafana.ini"
        ]
      }
      
      volume_mount {
        volume = "grafana_data"
        destination = "/var/lib/grafana"
      }
      
      template {
        data = <<EOF
[server]
protocol = http
http_port = {{ env "NOMAD_PORT_http" }}
domain = localhost

[security]
admin_user = admin
admin_password = {{ var.admin_password }}

[auth.anonymous]
enabled = false

[analytics]
reporting_enabled = false
check_for_updates = false

[log]
mode = console
level = info
EOF
        destination = "local/grafana.ini"
      }
      
      service {
        name = "grafana"
        port = "http"
        
        tags = [
          "monitoring",
          "dashboard",
          "eos-managed"
        ]
        
        check {
          type = "http"
          path = "/api/health"
          interval = "10s"
          timeout = "3s"
        }
      }
      
      resources {
        cpu = 100
        memory = 512
      }
      
      env {
        GF_SECURITY_ADMIN_PASSWORD = var.admin_password
        GF_INSTALL_PLUGINS = ""
      }
    }
  }
}