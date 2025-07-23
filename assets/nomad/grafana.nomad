job "grafana" {
  datacenters = ["dc1"]
  type        = "service"

  group "grafana" {
    count = 1

    network {
      port "http" {
        static = 3000
      }
    }

    task "grafana" {
      driver = "docker"

      config {
        image = "grafana/grafana:latest"
        ports = ["http"]
        
        volumes = [
          "local/grafana.ini:/etc/grafana/grafana.ini",
          "grafana-data:/var/lib/grafana",
          "local/provisioning:/etc/grafana/provisioning"
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
        GF_SECURITY_ADMIN_USER     = "admin"
        GF_SECURITY_ADMIN_PASSWORD = "${ADMIN_PASSWORD}"
        GF_INSTALL_PLUGINS         = "grafana-piechart-panel,grafana-worldmap-panel"
        GF_AUTH_PROXY_ENABLED      = "true"
        GF_AUTH_PROXY_HEADER_NAME  = "X-Auth-User"
        GF_AUTH_PROXY_HEADER_PROPERTY = "username"
        GF_AUTH_PROXY_AUTO_SIGN_UP = "true"
      }

      template {
        data = <<EOH
[server]
http_port = 3000
domain = grafana.${DOMAIN}
root_url = https://grafana.${DOMAIN}

[database]
type = postgres
host = postgres.service.consul:5432
name = grafana
user = grafana
password = ${DB_PASSWORD}

[session]
provider = redis
provider_config = addr=redis.service.consul:6379,pool_size=100,prefix=grafana

[auth]
disable_login_form = false

[auth.proxy]
enabled = true
header_name = X-Auth-User
header_property = username
auto_sign_up = true
sync_ttl = 60
whitelist = 
headers = 

[users]
allow_sign_up = false
allow_org_create = false
auto_assign_org = true
auto_assign_org_role = Viewer

[log]
mode = console
level = info

[alerting]
enabled = true
execute_alerts = true

[metrics]
enabled = true
interval_seconds = 60
EOH
        destination = "local/grafana.ini"
      }

      template {
        data = <<EOH
apiVersion: 1

datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus.service.consul:9090
    isDefault: true
    editable: true

  - name: Loki
    type: loki
    access: proxy
    url: http://loki.service.consul:3100
    editable: true
    jsonData:
      maxLines: 1000

  - name: Elasticsearch
    type: elasticsearch
    access: proxy
    url: http://elasticsearch.service.consul:9200
    database: "[logstash-]YYYY.MM.DD"
    editable: true
    jsonData:
      esVersion: 7
      timeField: "@timestamp"
      interval: Daily
      logMessageField: message
      logLevelField: level
EOH
        destination = "local/provisioning/datasources/default.yaml"
      }

      template {
        data = <<EOH
apiVersion: 1

providers:
  - name: 'EOS Dashboards'
    orgId: 1
    folder: 'EOS'
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    allowUiUpdates: true
    options:
      path: /etc/grafana/provisioning/dashboards
EOH
        destination = "local/provisioning/dashboards/default.yaml"
      }

      resources {
        cpu    = 500
        memory = 512
      }

      service {
        name = "grafana"
        port = "http"
        tags = ["monitoring", "ui"]

        check {
          type     = "http"
          path     = "/api/health"
          interval = "30s"
          timeout  = "5s"
        }
      }
    }
  }
}