job "hecate-redis" {
  datacenters = ["dc1"]
  type = "service"

  group "redis" {
    count = 1

    network {
      port "redis" {
        static = 6379
      }
    }

    service {
      name = "hecate-redis"
      port = "redis"
      
      check {
        type     = "tcp"
        port     = "redis"
        interval = "10s"
        timeout  = "2s"
      }
    }

    task "redis" {
      driver = "docker"

      config {
        image = "redis:7-alpine"
        ports = ["redis"]
        
        volumes = [
          "/opt/hecate/data/redis:/data"
        ]
        
        command = "redis-server"
        args = ["--requirepass", "${REDIS_PASSWORD}"]
      }

      template {
        data = <<EOH
{{ with secret "secret/hecate/redis/password" }}
REDIS_PASSWORD={{ .Data.data.value }}
{{ end }}
EOH
        destination = "secrets/env"
        env         = true
      }

      resources {
        cpu    = 256
        memory = 256
      }
    }
  }
}