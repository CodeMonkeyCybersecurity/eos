job "clusterfuzz-core" {
  datacenters = ["dc1"]
  type = "service"
  
  update {
    max_parallel = 1
    min_healthy_time = "10s"
    healthy_deadline = "5m"
    auto_revert = true
  }

  
  group "database" {
    count = 1
    
    network {
      port "db" {
        static = 5432
      }
    }
    
    service {
      name = "clusterfuzz-postgres"
      port = "db"
      
      check {
        type = "tcp"
        interval = "10s"
        timeout = "2s"
      }
    }
    
    task "postgres" {
      driver = "docker"
      
      config {
        image = "postgres:15"
        ports = ["db"]
        
        volumes = [
          "local/init:/docker-entrypoint-initdb.d"
        ]
      }
      
      template {
        data = <<EOF
#!/bin/bash
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE DATABASE clusterfuzz;
    GRANT ALL PRIVILEGES ON DATABASE clusterfuzz TO $POSTGRES_USER;
EOSQL
EOF
        destination = "local/init/01-create-db.sh"
        perms = "755"
      }
      
      env {
        POSTGRES_USER = "clusterfuzz"
        POSTGRES_PASSWORD = "72fe71f3cdb5010cfc53006afa015eda"
        POSTGRES_DB = "clusterfuzz"
      }
      
      resources {
        cpu    = 2000
        memory = 4096
      }
    }
  }
  

  
  group "queue" {
    count = 1
    
    network {
      port "redis" {
        static = 6379
      }
    }
    
    service {
      name = "clusterfuzz-redis"
      port = "redis"
      
      check {
        type = "tcp"
        interval = "10s"
        timeout = "2s"
      }
    }
    
    task "redis" {
      driver = "docker"
      
      config {
        image = "redis:7-alpine"
        ports = ["redis"]
        command = "redis-server"
        args = ["--requirepass", "ebd9536c5d728fc428ef8d02f0a1375b"]
      }
      
      resources {
        cpu    = 500
        memory = 1024
      }
    }
  }
  

  
}