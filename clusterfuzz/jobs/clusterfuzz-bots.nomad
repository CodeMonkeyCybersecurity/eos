job "clusterfuzz-bots" {
  datacenters = ["dc1"]
  type = "batch"
  
  parameterized {
    payload = "optional"
  }
  
  group "bot" {
    count = 3
    
    task "fuzzer" {
      driver = "docker"
      
      config {
        image = "clusterfuzz/bot:latest"
        
        volumes = [
          "local/config:/config"
        ]
      }
      
      template {
        data = <<EOF

CLUSTERFUZZ_DB_HOST=clusterfuzz-postgres.service.consul
CLUSTERFUZZ_DB_PORT=5432
CLUSTERFUZZ_DB_NAME=clusterfuzz
CLUSTERFUZZ_DB_USER=clusterfuzz
CLUSTERFUZZ_DB_PASS=72fe71f3cdb5010cfc53006afa015eda
CLUSTERFUZZ_QUEUE_HOST=clusterfuzz-redis.service.consul
CLUSTERFUZZ_QUEUE_PORT=6379
CLUSTERFUZZ_QUEUE_PASS=ebd9536c5d728fc428ef8d02f0a1375b


EOF
        destination = "local/config/bot.env"
        env = true
      }
      
      resources {
        cpu    = 2000
        memory = 4096
      }
    }
  }
  
  
  group "preemptible-bot" {
    count = 5
    
    constraint {
      attribute = "${node.class}"
      value     = "preemptible"
    }
    
    task "fuzzer" {
      driver = "docker"
      
      config {
        image = "clusterfuzz/bot:latest"
        
        volumes = [
          "local/config:/config"
        ]
      }
      
      template {
        data = <<EOF

CLUSTERFUZZ_DB_HOST=clusterfuzz-postgres.service.consul
CLUSTERFUZZ_DB_PORT=5432
CLUSTERFUZZ_DB_NAME=clusterfuzz
CLUSTERFUZZ_DB_USER=clusterfuzz
CLUSTERFUZZ_DB_PASS=72fe71f3cdb5010cfc53006afa015eda
CLUSTERFUZZ_QUEUE_HOST=clusterfuzz-redis.service.consul
CLUSTERFUZZ_QUEUE_PORT=6379
CLUSTERFUZZ_QUEUE_PASS=ebd9536c5d728fc428ef8d02f0a1375b


EOF
        destination = "local/config/bot.env"
        env = true
      }
      
      resources {
        cpu    = 2000
        memory = 4096
      }
    }
  }
  
}