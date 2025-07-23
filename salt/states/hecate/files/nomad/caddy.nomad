job "hecate-caddy" {
  datacenters = ["dc1"]
  type = "service"

  group "caddy" {
    count = 1

    network {
      port "http" {
        static = 80
      }
      port "https" {
        static = 443
      }
      port "admin" {
        static = 2019
      }
    }

    service {
      name = "hecate-caddy"
      port = "http"
      
      check {
        type     = "http"
        path     = "/health"
        port     = "admin"
        interval = "10s"
        timeout  = "3s"
      }
    }

    task "caddy" {
      driver = "docker"

      config {
        image = "caddy:2-alpine"
        ports = ["http", "https", "admin"]
        
        volumes = [
          "/opt/hecate/caddy:/config",
          "/opt/hecate/data/caddy:/data"
        ]
        
        args = ["caddy", "run", "--config", "/config/Caddyfile", "--adapter", "caddyfile"]
      }

      resources {
        cpu    = 256
        memory = 256
      }
    }
  }
}