job "vault" {
  datacenters = ["dc1"]
  type        = "service"

  group "vault" {
    count = 1

    network {
      port "http" {
        static = 8200
      }
      port "cluster" {
        static = 8201
      }
    }

    task "vault" {
      driver = "docker"

      config {
        image = "hashicorp/vault:latest"
        ports = ["http", "cluster"]
        
        cap_add = ["IPC_LOCK"]
        
        volumes = [
          "local/vault.hcl:/vault/config/vault.hcl",
          "vault-data:/vault/data"
        ]

        logging {
          type = "json-file"
          config {
            max-size = "10m"
            max-file = "3"
          }
        }
      }

      env {
        VAULT_ADDR = "http://127.0.0.1:8200"
        VAULT_API_ADDR = "http://${NOMAD_IP_http}:8200"
        VAULT_CLUSTER_ADDR = "http://${NOMAD_IP_cluster}:8201"
      }

      template {
        data = <<EOH
ui = true
disable_mlock = true

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = 1
  
  # Enable CORS for UI
  cors {
    enabled = true
    allowed_origins = ["*"]
  }
}

storage "consul" {
  address = "consul.service.consul:8500"
  path    = "vault/"
  token   = "${CONSUL_TOKEN}"
}

service_registration "consul" {
  address = "consul.service.consul:8500"
  token   = "${CONSUL_TOKEN}"
}

cluster_name = "eos-vault"

# Enable telemetry
telemetry {
  prometheus_retention_time = "30s"
  disable_hostname = true
}

# API rate limiting
api_addr = "http://${NOMAD_IP_http}:8200"
cluster_addr = "http://${NOMAD_IP_cluster}:8201"

# Performance tuning
default_lease_ttl = "168h"
max_lease_ttl = "720h"

# Audit logging
audit {
  enabled = true
  path = "file"
  
  options = {
    file_path = "/vault/logs/audit.log"
    log_raw = false
    hmac_accessor = true
    mode = "0600"
    format = "json"
  }
}
EOH
        destination = "local/vault.hcl"
      }

      resources {
        cpu    = 500
        memory = 512
      }

      service {
        name = "vault"
        port = "http"
        tags = ["security", "secrets", "ui"]

        check {
          type     = "http"
          path     = "/v1/sys/health"
          interval = "30s"
          timeout  = "5s"
          
          check_restart {
            limit = 3
            grace = "90s"
          }
        }
      }

      service {
        name = "vault-cluster"
        port = "cluster"
        tags = ["security", "secrets", "cluster"]

        check {
          type     = "tcp"
          interval = "30s"
          timeout  = "5s"
        }
      }
    }
  }
}