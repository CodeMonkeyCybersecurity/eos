job "kibana" {
  datacenters = ["dc1"]
  type        = "service"

  group "kibana" {
    count = 1

    network {
      port "http" {
        static = 5601
      }
    }

    task "kibana" {
      driver = "docker"

      config {
        image = "docker.elastic.co/kibana/kibana:8.11.0"
        ports = ["http"]
        
        volumes = [
          "local/kibana.yml:/usr/share/kibana/config/kibana.yml"
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
        ELASTICSEARCH_HOSTS = "http://elasticsearch.service.consul:9200"
        ELASTICSEARCH_USERNAME = "kibana_system"
        ELASTICSEARCH_PASSWORD = "${KIBANA_PASSWORD}"
      }

      template {
        data = <<EOH
server.name: kibana.eos.local
server.host: "0.0.0.0"
server.port: 5601

elasticsearch.hosts: ["http://elasticsearch.service.consul:9200"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "${KIBANA_PASSWORD}"

# Security
xpack.security.enabled: true
xpack.encryptedSavedObjects.encryptionKey: "${ENCRYPTION_KEY}"
xpack.reporting.encryptionKey: "${REPORTING_KEY}"
xpack.security.encryptionKey: "${SECURITY_KEY}"

# Monitoring
monitoring.ui.enabled: true
monitoring.ui.container.elasticsearch.enabled: true

# Logging
logging.dest: stdout
logging.verbose: false
logging.quiet: false

# Advanced settings
elasticsearch.requestTimeout: 30000
elasticsearch.pingTimeout: 30000
elasticsearch.shardTimeout: 30000

# UI settings
server.defaultRoute: /app/home
server.basePath: ""
server.rewriteBasePath: false

# Saved objects
savedObjects.maxImportPayloadBytes: 26214400

# Session
xpack.security.session.idleTimeout: "1h"
xpack.security.session.lifespan: "8h"

# Telemetry
telemetry.enabled: false
telemetry.optIn: false
EOH
        destination = "local/kibana.yml"
      }

      resources {
        cpu    = 1000
        memory = 2048
      }

      service {
        name = "kibana"
        port = "http"
        tags = ["monitoring", "ui", "analytics"]

        check {
          type     = "http"
          path     = "/api/status"
          interval = "30s"
          timeout  = "5s"
        }
      }
    }
  }
}