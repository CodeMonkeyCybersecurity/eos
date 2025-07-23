job "wazuh" {
  datacenters = ["dc1"]
  type        = "service"

  group "wazuh-manager" {
    count = 1

    network {
      port "api" {
        static = 55000
      }
      port "registration" {
        static = 1514
      }
      port "agent" {
        static = 1515
      }
    }

    task "wazuh-manager" {
      driver = "docker"

      config {
        image = "wazuh/wazuh-manager:latest"
        ports = ["api", "registration", "agent"]
        
        volumes = [
          "local/ossec.conf:/var/ossec/etc/ossec.conf",
          "wazuh-manager-data:/var/ossec/data",
          "wazuh-manager-logs:/var/ossec/logs",
          "wazuh-manager-queue:/var/ossec/queue",
          "wazuh-manager-etc:/var/ossec/etc",
          "wazuh-manager-integrations:/var/ossec/integrations",
          "wazuh-manager-active-response:/var/ossec/active-response",
          "wazuh-manager-wodles:/var/ossec/wodles",
          "wazuh-manager-backup:/var/ossec/backup"
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
        INDEXER_URL       = "https://elasticsearch.service.consul:9200"
        INDEXER_USERNAME  = "admin"
        INDEXER_PASSWORD  = "${INDEXER_PASSWORD}"
        FILEBEAT_SSL_VERIFICATION_MODE = "none"
        SSL_CERTIFICATE_AUTHORITIES = ""
        SSL_CERTIFICATE = ""
        SSL_KEY = ""
        API_USERNAME = "wazuh"
        API_PASSWORD = "${API_PASSWORD}"
      }

      template {
        data = <<EOH
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>smtp.example.wazuh.com</smtp_server>
    <email_from>wazuh@example.wazuh.com</email_from>
    <email_to>recipient@example.wazuh.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
  </global>

  <cluster>
    <name>wazuh-cluster</name>
    <node_name>master</node_name>
    <node_type>master</node_type>
    <key>${CLUSTER_KEY}</key>
    <port>1516</port>
    <bind_addr>0.0.0.0</bind_addr>
    <nodes>
      <node>master</node>
    </nodes>
    <hidden>no</hidden>
    <disabled>no</disabled>
  </cluster>
</ossec_config>
EOH
        destination = "local/ossec.conf"
      }

      resources {
        cpu    = 2000
        memory = 4096
      }

      service {
        name = "wazuh"
        port = "api"
        tags = ["api", "security"]

        check {
          type     = "http"
          path     = "/api/health"
          interval = "30s"
          timeout  = "5s"
        }
      }

      service {
        name = "wazuh-registration"
        port = "registration"
        tags = ["registration", "security"]

        check {
          type     = "tcp"
          interval = "30s"
          timeout  = "5s"
        }
      }

      service {
        name = "wazuh-agent"
        port = "agent"
        tags = ["agent", "security"]

        check {
          type     = "tcp"
          interval = "30s"
          timeout  = "5s"
        }
      }
    }
  }
}