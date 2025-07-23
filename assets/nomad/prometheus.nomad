job "prometheus" {
  datacenters = ["dc1"]
  type        = "service"

  group "prometheus" {
    count = 1

    network {
      port "http" {
        static = 9090
      }
    }

    task "prometheus" {
      driver = "docker"

      config {
        image = "prom/prometheus:latest"
        ports = ["http"]
        
        args = [
          "--config.file=/etc/prometheus/prometheus.yml",
          "--storage.tsdb.path=/prometheus",
          "--storage.tsdb.retention.time=15d",
          "--web.console.libraries=/usr/share/prometheus/console_libraries",
          "--web.console.templates=/usr/share/prometheus/consoles",
          "--web.enable-lifecycle"
        ]
        
        volumes = [
          "local/prometheus.yml:/etc/prometheus/prometheus.yml",
          "local/alerts.yml:/etc/prometheus/alerts.yml",
          "prometheus-data:/prometheus"
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
global:
  scrape_interval:     15s
  evaluation_interval: 15s
  external_labels:
    cluster: 'eos'
    environment: '{{ env "NOMAD_DC" }}'

alerting:
  alertmanagers:
    - static_configs:
        - targets: []

rule_files:
  - /etc/prometheus/alerts.yml

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'nomad'
    consul_sd_configs:
      - server: 'consul.service.consul:8500'
        services: ['nomad-client', 'nomad']
    relabel_configs:
      - source_labels: ['__meta_consul_service']
        target_label: 'job'
      - source_labels: ['__meta_consul_node']
        target_label: 'instance'

  - job_name: 'consul'
    consul_sd_configs:
      - server: 'consul.service.consul:8500'
        services: ['consul']
    relabel_configs:
      - source_labels: ['__meta_consul_service']
        target_label: 'job'
      - source_labels: ['__meta_consul_node']
        target_label: 'instance'

  - job_name: 'vault'
    consul_sd_configs:
      - server: 'consul.service.consul:8500'
        services: ['vault']
    relabel_configs:
      - source_labels: ['__meta_consul_service']
        target_label: 'job'
      - source_labels: ['__meta_consul_node']
        target_label: 'instance'

  - job_name: 'caddy'
    consul_sd_configs:
      - server: 'consul.service.consul:8500'
        services: ['caddy']
    relabel_configs:
      - source_labels: ['__meta_consul_service']
        target_label: 'job'
      - source_labels: ['__meta_consul_node']
        target_label: 'instance'

  - job_name: 'node_exporter'
    consul_sd_configs:
      - server: 'consul.service.consul:8500'
        services: ['node-exporter']
    relabel_configs:
      - source_labels: ['__meta_consul_service']
        target_label: 'job'
      - source_labels: ['__meta_consul_node']
        target_label: 'instance'
EOH
        destination = "local/prometheus.yml"
      }

      template {
        data = <<EOH
groups:
  - name: eos_alerts
    interval: 30s
    rules:
      - alert: InstanceDown
        expr: up == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Instance {{ $labels.instance }} down"
          description: "{{ $labels.instance }} of job {{ $labels.job }} has been down for more than 5 minutes."

      - alert: HighCPUUsage
        expr: (100 - (avg by (instance) (irate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)) > 80
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High CPU usage on {{ $labels.instance }}"
          description: "CPU usage is above 80% (current value: {{ $value }}%)"

      - alert: HighMemoryUsage
        expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100 > 80
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage on {{ $labels.instance }}"
          description: "Memory usage is above 80% (current value: {{ $value }}%)"

      - alert: DiskSpaceLow
        expr: (node_filesystem_avail_bytes{mountpoint="/"} / node_filesystem_size_bytes{mountpoint="/"}) * 100 < 20
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Low disk space on {{ $labels.instance }}"
          description: "Disk space is below 20% (current value: {{ $value }}%)"
EOH
        destination = "local/alerts.yml"
      }

      resources {
        cpu    = 1000
        memory = 2048
      }

      service {
        name = "prometheus"
        port = "http"
        tags = ["monitoring", "metrics"]

        check {
          type     = "http"
          path     = "/-/healthy"
          interval = "30s"
          timeout  = "5s"
        }
      }
    }
  }
}