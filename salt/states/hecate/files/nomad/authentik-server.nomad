job "hecate-authentik-server" {
  datacenters = ["dc1"]
  type = "service"

  group "authentik-server" {
    count = 1

    network {
      port "http" {
        static = 9000
      }
      port "https" {
        static = 9443
      }
    }

    service {
      name = "hecate-authentik-server"
      port = "http"
      
      check {
        type     = "http"
        path     = "/-/health/ready/"
        port     = "http"
        interval = "30s"
        timeout  = "5s"
      }
    }

    task "authentik-server" {
      driver = "docker"

      config {
        image = "ghcr.io/goauthentik/server:2024.2"
        ports = ["http", "https"]
        
        command = "server"
      }

      template {
        data = <<EOH
{{ with secret "secret/hecate/postgres/password" }}
AUTHENTIK_POSTGRESQL__PASSWORD={{ .Data.data.value }}
{{ end }}
{{ with secret "secret/hecate/redis/password" }}
AUTHENTIK_REDIS__PASSWORD={{ .Data.data.value }}
{{ end }}
{{ with secret "secret/hecate/authentik/secret_key" }}
AUTHENTIK_SECRET_KEY={{ .Data.data.value }}
{{ end }}
AUTHENTIK_POSTGRESQL__HOST=hecate-postgres.service.consul
AUTHENTIK_POSTGRESQL__USER=authentik
AUTHENTIK_POSTGRESQL__NAME=authentik
AUTHENTIK_POSTGRESQL__PORT=5432
AUTHENTIK_REDIS__HOST=hecate-redis.service.consul
AUTHENTIK_REDIS__PORT=6379
AUTHENTIK_ERROR_REPORTING__ENABLED=false
AUTHENTIK_LOG_LEVEL=info
EOH
        destination = "secrets/env"
        env         = true
      }

      resources {
        cpu    = 1000
        memory = 1024
      }
    }
  }
}