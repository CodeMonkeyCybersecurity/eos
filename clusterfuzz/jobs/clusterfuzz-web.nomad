job "clusterfuzz-web" {
  datacenters = ["dc1"]
  type = "service"
  
  group "web" {
    count = 1
    
    network {
      port "http" {
        to = 8080
      }
    }
    
    service {
      name = "clusterfuzz-web"
      port = "http"
      
      tags = [
        "traefik.enable=true",
        "traefik.http.routers.clusterfuzz.rule=Host(`clusterfuzz.local`)",
        "traefik.http.routers.clusterfuzz.tls=true",
        "traefik.http.routers.clusterfuzz.tls.certresolver=letsencrypt"
      ]
      
      check {
        type = "http"
        path = "/health"
        interval = "10s"
        timeout = "2s"
      }
    }
    
    task "web" {
      driver = "docker"
      
      config {
        image = "clusterfuzz/web:latest"
        ports = ["http"]
      }
      
      env {
        CLUSTERFUZZ_DB_HOST = "clusterfuzz-postgres.service.consul"
        CLUSTERFUZZ_DB_PORT = "5432"
        CLUSTERFUZZ_DB_NAME = "clusterfuzz"
        CLUSTERFUZZ_DB_USER = "clusterfuzz"
        CLUSTERFUZZ_DB_PASS = "72fe71f3cdb5010cfc53006afa015eda"
        CLUSTERFUZZ_DOMAIN = "clusterfuzz.local"
      }
      
      resources {
        cpu    = 1000
        memory = 2048
      }
    }
  }
}