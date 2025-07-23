job "hecate-postgres" {
  datacenters = ["dc1"]
  type = "service"

  group "postgres" {
    count = 1

    network {
      port "db" {
        static = 5432
      }
    }

    service {
      name = "hecate-postgres"
      port = "db"
      
      check {
        type     = "tcp"
        port     = "db"
        interval = "10s"
        timeout  = "2s"
      }
    }

    task "postgres" {
      driver = "docker"

      config {
        image = "postgres:15-alpine"
        ports = ["db"]
        
        volumes = [
          "/opt/hecate/data/postgres:/var/lib/postgresql/data"
        ]
      }

      template {
        data = <<EOH
POSTGRES_USER=authentik
POSTGRES_DB=authentik
{{ with secret "secret/hecate/postgres/root_password" }}
POSTGRES_PASSWORD={{ .Data.data.value }}
{{ end }}
{{ with secret "secret/hecate/postgres/password" }}
POSTGRES_AUTHENTIK_PASSWORD={{ .Data.data.value }}
{{ end }}
EOH
        destination = "secrets/env"
        env         = true
      }

      resources {
        cpu    = 500
        memory = 512
      }
    }
  }
}