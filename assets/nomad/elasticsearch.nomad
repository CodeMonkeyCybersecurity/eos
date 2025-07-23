job "elasticsearch" {
  datacenters = ["dc1"]
  type        = "service"

  group "elasticsearch" {
    count = 1

    network {
      port "http" {
        static = 9200
      }
      port "transport" {
        static = 9300
      }
    }

    task "elasticsearch" {
      driver = "docker"

      config {
        image = "docker.elastic.co/elasticsearch/elasticsearch:8.11.0"
        ports = ["http", "transport"]
        
        volumes = [
          "elasticsearch-data:/usr/share/elasticsearch/data",
          "local/elasticsearch.yml:/usr/share/elasticsearch/config/elasticsearch.yml"
        ]

        ulimit {
          memlock {
            soft = -1
            hard = -1
          }
          nofile {
            soft = 65536
            hard = 65536
          }
        }

        logging {
          type = "json-file"
          config {
            max-size = "10m"
            max-file = "3"
          }
        }
      }

      env {
        ES_JAVA_OPTS = "-Xms2g -Xmx2g"
        ELASTIC_PASSWORD = "${ELASTIC_PASSWORD}"
        discovery.type = "single-node"
        xpack.security.enabled = "true"
        xpack.security.http.ssl.enabled = "false"
        xpack.security.transport.ssl.enabled = "false"
      }

      template {
        data = <<EOH
cluster.name: eos-cluster
node.name: es-node-1
network.host: 0.0.0.0
http.port: 9200
transport.port: 9300

# Discovery
discovery.type: single-node

# Security
xpack.security.enabled: true
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false

# Monitoring
xpack.monitoring.collection.enabled: true

# Machine Learning
xpack.ml.enabled: false

# Memory
indices.memory.index_buffer_size: 30%
indices.memory.min_index_buffer_size: 96mb

# Threading
thread_pool.search.size: 20
thread_pool.search.queue_size: 10000
thread_pool.get.size: 10
thread_pool.get.queue_size: 1000
thread_pool.write.size: 10
thread_pool.write.queue_size: 10000

# Circuit breakers
indices.breaker.total.use_real_memory: false
indices.breaker.total.limit: 70%
indices.breaker.request.limit: 60%
indices.breaker.fielddata.limit: 60%

# Indexing
index.refresh_interval: 5s
index.max_result_window: 10000
EOH
        destination = "local/elasticsearch.yml"
      }

      resources {
        cpu    = 2000
        memory = 4096
      }

      service {
        name = "elasticsearch"
        port = "http"
        tags = ["database", "search"]

        check {
          type     = "http"
          path     = "/_cluster/health"
          interval = "30s"
          timeout  = "5s"
          header {
            Authorization = ["Basic ${ELASTIC_AUTH}"]
          }
        }
      }

      service {
        name = "elasticsearch-transport"
        port = "transport"
        tags = ["database", "search", "transport"]

        check {
          type     = "tcp"
          interval = "30s"
          timeout  = "5s"
        }
      }
    }
  }
}