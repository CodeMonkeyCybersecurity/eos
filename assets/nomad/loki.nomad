job "loki" {
  datacenters = ["dc1"]
  type        = "service"

  group "loki" {
    count = 1

    network {
      port "http" {
        static = 3100
      }
      port "grpc" {
        static = 9095
      }
    }

    task "loki" {
      driver = "docker"

      config {
        image = "grafana/loki:latest"
        ports = ["http", "grpc"]
        
        args = [
          "-config.file=/etc/loki/loki.yml"
        ]
        
        volumes = [
          "local/loki.yml:/etc/loki/loki.yml",
          "loki-data:/loki"
        ]

        logging {
          type = "json-file"
          config {
            max-size = "10m"
            max-file = "3"
          }
        }
      }

      template {
        data = <<EOH
auth_enabled: false

server:
  http_listen_port: 3100
  grpc_listen_port: 9095

common:
  path_prefix: /loki
  storage:
    filesystem:
      chunks_directory: /loki/chunks
      rules_directory: /loki/rules
  replication_factor: 1
  ring:
    instance_addr: 127.0.0.1
    kvstore:
      store: inmemory

schema_config:
  configs:
    - from: 2020-10-24
      store: boltdb-shipper
      object_store: filesystem
      schema: v11
      index:
        prefix: index_
        period: 24h

ruler:
  alertmanager_url: http://localhost:9093

analytics:
  reporting_enabled: false

limits_config:
  enforce_metric_name: false
  reject_old_samples: true
  reject_old_samples_max_age: 168h
  ingestion_rate_mb: 10
  ingestion_burst_size_mb: 20
  per_stream_rate_limit: 10MB
  per_stream_rate_limit_burst: 20MB

chunk_store_config:
  max_look_back_period: 0s

table_manager:
  retention_deletes_enabled: true
  retention_period: 744h # 31 days

compactor:
  working_directory: /loki/compactor
  shared_store: filesystem
  compaction_interval: 10m
  retention_enabled: true
  retention_delete_delay: 2h
  retention_delete_worker_count: 150
EOH
        destination = "local/loki.yml"
      }

      resources {
        cpu    = 500
        memory = 1024
      }

      service {
        name = "loki"
        port = "http"
        tags = ["monitoring", "logs"]

        check {
          type     = "http"
          path     = "/ready"
          interval = "30s"
          timeout  = "5s"
        }
      }

      service {
        name = "loki-grpc"
        port = "grpc"
        tags = ["monitoring", "logs", "grpc"]

        check {
          type     = "tcp"
          interval = "30s"
          timeout  = "5s"
        }
      }
    }
  }
}